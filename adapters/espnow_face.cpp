/**
 * @file espnow_face.cpp
 * @brief ESP-NOW Face implementation
 */

#include "espnow_face.hpp"

#include <cstring>

#include "esp_log.h"
#include "esp_wifi.h"

namespace {
const char* TAG = "espnow_face";
}  // namespace

namespace ndn {

// Static instance
EspNowFace* EspNowFace::instance_ = nullptr;

EspNowFace::EspNowFace(FaceId faceId) : faceId_(faceId) {
    // Initialize peer array
    for (auto& peer : peers_) {
        peer.inUse = false;
    }

    // Initialize receive queue
    for (auto& pkt : rxQueue_) {
        pkt.valid = false;
    }
}

EspNowFace::~EspNowFace() {
    stop();
}

Error EspNowFace::start() {
    if (running_) {
        return Error::Success;
    }

    // Set static instance
    instance_ = this;

    // Initialize ESP-NOW
    esp_err_t ret = esp_now_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_now_init failed: %s", esp_err_to_name(ret));
        return Error::SendFailed;
    }

    // Register callbacks
    ret = esp_now_register_recv_cb(onReceive);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_now_register_recv_cb failed: %s", esp_err_to_name(ret));
        esp_now_deinit();
        return Error::SendFailed;
    }

    ret = esp_now_register_send_cb(onSend);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_now_register_send_cb failed: %s", esp_err_to_name(ret));
        esp_now_deinit();
        return Error::SendFailed;
    }

    // Add broadcast peer
    esp_now_peer_info_t broadcastPeer = {};
    std::memcpy(broadcastPeer.peer_addr, BROADCAST_MAC, 6);
    broadcastPeer.channel = 0;  // Current channel
    broadcastPeer.ifidx = WIFI_IF_STA;
    broadcastPeer.encrypt = false;

    ret = esp_now_add_peer(&broadcastPeer);
    if (ret != ESP_OK && ret != ESP_ERR_ESPNOW_EXIST) {
        ESP_LOGE(TAG, "esp_now_add_peer (broadcast) failed: %s", esp_err_to_name(ret));
        esp_now_deinit();
        return Error::SendFailed;
    }

    running_ = true;
    ESP_LOGI(TAG, "ESP-NOW Face started (id=%u)", faceId_);

    return Error::Success;
}

void EspNowFace::stop() {
    if (!running_) {
        return;
    }

    esp_now_unregister_recv_cb();
    esp_now_unregister_send_cb();
    esp_now_deinit();

    running_ = false;
    instance_ = nullptr;

    ESP_LOGI(TAG, "ESP-NOW Face stopped");
}

Error EspNowFace::send(const uint8_t* data, size_t len) {
    // Default is broadcast
    return broadcast(data, len);
}

Error EspNowFace::sendTo(FaceId destFace, const uint8_t* data, size_t len) {
    if (!running_) {
        return Error::SendFailed;
    }

    if (len > ESPNOW_MAX_PAYLOAD) {
        return Error::BufferTooSmall;
    }

    // Look up MAC address from FaceId
    const PeerInfo* peer = findPeer(destFace);
    if (peer == nullptr) {
        ESP_LOGW(TAG, "Peer not found for faceId=%u", destFace);
        return Error::NotFound;
    }

    // Add peer if not registered
    if (!esp_now_is_peer_exist(peer->mac)) {
        esp_now_peer_info_t peerInfo = {};
        std::memcpy(peerInfo.peer_addr, peer->mac, 6);
        peerInfo.channel = 0;
        peerInfo.ifidx = WIFI_IF_STA;
        peerInfo.encrypt = false;

        esp_err_t ret = esp_now_add_peer(&peerInfo);
        if (ret != ESP_OK && ret != ESP_ERR_ESPNOW_EXIST) {
            ESP_LOGE(TAG, "esp_now_add_peer failed: %s", esp_err_to_name(ret));
            return Error::SendFailed;
        }
    }

    esp_err_t ret = esp_now_send(peer->mac, data, len);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_now_send failed: %s", esp_err_to_name(ret));
        return Error::SendFailed;
    }

    return Error::Success;
}

Error EspNowFace::broadcast(const uint8_t* data, size_t len) {
    if (!running_) {
        return Error::SendFailed;
    }

    if (len > ESPNOW_MAX_PAYLOAD) {
        return Error::BufferTooSmall;
    }

    esp_err_t ret = esp_now_send(BROADCAST_MAC, data, len);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_now_send (broadcast) failed: %s", esp_err_to_name(ret));
        return Error::SendFailed;
    }

    return Error::Success;
}

FaceId EspNowFace::addPeer(const uint8_t* mac) {
    // Search for existing peer
    PeerInfo* existing = findPeerByMac(mac);
    if (existing != nullptr) {
        existing->lastSeen = currentTimeMs();
        return existing->faceId;
    }

    // Search for empty slot
    for (auto& peer : peers_) {
        if (!peer.inUse) {
            std::memcpy(peer.mac, mac, 6);
            peer.faceId = macToFaceId(mac);
            peer.inUse = true;
            peer.lastSeen = currentTimeMs();

            // Register as ESP-NOW peer
            if (!esp_now_is_peer_exist(mac)) {
                esp_now_peer_info_t peerInfo = {};
                std::memcpy(peerInfo.peer_addr, mac, 6);
                peerInfo.channel = 0;
                peerInfo.ifidx = WIFI_IF_STA;
                peerInfo.encrypt = false;
                esp_now_add_peer(&peerInfo);
            }

            ESP_LOGI(TAG, "Peer added: %02x:%02x:%02x:%02x:%02x:%02x -> faceId=%u", mac[0], mac[1],
                     mac[2], mac[3], mac[4], mac[5], peer.faceId);

            return peer.faceId;
        }
    }

    ESP_LOGW(TAG, "Peer table full");
    return FACE_ID_INVALID;
}

void EspNowFace::removePeer(FaceId faceId) {
    PeerInfo* peer = findPeer(faceId);
    if (peer != nullptr) {
        esp_now_del_peer(peer->mac);
        peer->inUse = false;
        ESP_LOGI(TAG, "Peer removed: faceId=%u", faceId);
    }
}

bool EspNowFace::getMacAddress(FaceId faceId, uint8_t* mac) const {
    const PeerInfo* peer = findPeer(faceId);
    if (peer != nullptr) {
        std::memcpy(mac, peer->mac, 6);
        return true;
    }
    return false;
}

size_t EspNowFace::peerCount() const {
    size_t count = 0;
    for (const auto& peer : peers_) {
        if (peer.inUse) {
            ++count;
        }
    }
    return count;
}

void EspNowFace::processReceiveQueue() {
    while (rxQueueHead_ != rxQueueTail_) {
        RxPacket& pkt = rxQueue_[rxQueueHead_];
        if (pkt.valid) {
            handleReceive(pkt.srcMac, pkt.data, pkt.len);
            pkt.valid = false;
        }
        rxQueueHead_ = (rxQueueHead_ + 1) % RX_QUEUE_SIZE;
    }
}

void EspNowFace::onReceive(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
    if (instance_ == nullptr || len <= 0 || static_cast<size_t>(len) > ESPNOW_MAX_PAYLOAD) {
        return;
    }

    // Add to receive queue (lightweight since in ISR context)
    const size_t nextTail = (instance_->rxQueueTail_ + 1) % RX_QUEUE_SIZE;
    if (nextTail != instance_->rxQueueHead_) {
        RxPacket& pkt = instance_->rxQueue_[instance_->rxQueueTail_];
        std::memcpy(pkt.srcMac, info->src_addr, 6);
        std::memcpy(pkt.data, data, len);
        pkt.len = static_cast<size_t>(len);
        pkt.valid = true;
        instance_->rxQueueTail_ = nextTail;
    } else {
        ESP_LOGW(TAG, "RX queue full, packet dropped");
    }
}

void EspNowFace::onSend(const esp_now_send_info_t* info, esp_now_send_status_t status) {
    if (status != ESP_NOW_SEND_SUCCESS && info != nullptr && info->des_addr != nullptr) {
        const uint8_t* mac = info->des_addr;
        ESP_LOGD(TAG, "Send failed to %02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
                 mac[3], mac[4], mac[5]);
    }
}

void EspNowFace::handleReceive(const uint8_t* srcMac, const uint8_t* data, size_t len) {
    // MAC address filter check
    if (macFilterEnabled_) {
        bool allowed = false;
        for (size_t i = 0; i < macFilterCount_; ++i) {
            if (std::memcmp(srcMac, macFilters_[i], 6) == 0) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            // Drop packets not matching the filter
            ESP_LOGD(TAG, "Packet filtered: %02x:%02x:%02x:%02x:%02x:%02x", srcMac[0], srcMac[1],
                     srcMac[2], srcMac[3], srcMac[4], srcMac[5]);
            return;
        }
    }

    // Auto-register sender as peer
    FaceId srcFaceId = addPeer(srcMac);
    if (srcFaceId == FACE_ID_INVALID) {
        srcFaceId = macToFaceId(srcMac);  // Use temporary ID even when table is full
    }

    // Invoke callback
    onPacketReceived(srcFaceId, data, len);
}

void EspNowFace::setMacFilter(const uint8_t* mac) {
    if (mac == nullptr) {
        clearMacFilters();
    } else {
        setMacFilters(reinterpret_cast<const uint8_t(*)[6]>(mac), 1);
    }
}

void EspNowFace::setMacFilters(const uint8_t macs[][6], size_t count) {
    if (count == 0) {
        clearMacFilters();
        return;
    }

    macFilterCount_ = (count > MAX_MAC_FILTERS) ? MAX_MAC_FILTERS : count;
    for (size_t i = 0; i < macFilterCount_; ++i) {
        std::memcpy(macFilters_[i], macs[i], 6);
    }
    macFilterEnabled_ = true;

    ESP_LOGI(TAG, "MAC filter enabled: %zu addresses", macFilterCount_);
    for (size_t i = 0; i < macFilterCount_; ++i) {
        ESP_LOGI(TAG, "  [%zu] %02x:%02x:%02x:%02x:%02x:%02x", i, macFilters_[i][0],
                 macFilters_[i][1], macFilters_[i][2], macFilters_[i][3], macFilters_[i][4],
                 macFilters_[i][5]);
    }
}

void EspNowFace::clearMacFilters() {
    macFilterEnabled_ = false;
    macFilterCount_ = 0;
    ESP_LOGI(TAG, "MAC filter disabled");
}

PeerInfo* EspNowFace::findPeer(FaceId faceId) {
    for (auto& peer : peers_) {
        if (peer.inUse && peer.faceId == faceId) {
            return &peer;
        }
    }
    return nullptr;
}

PeerInfo* EspNowFace::findPeerByMac(const uint8_t* mac) {
    for (auto& peer : peers_) {
        if (peer.inUse && std::memcmp(peer.mac, mac, 6) == 0) {
            return &peer;
        }
    }
    return nullptr;
}

const PeerInfo* EspNowFace::findPeer(FaceId faceId) const {
    for (const auto& peer : peers_) {
        if (peer.inUse && peer.faceId == faceId) {
            return &peer;
        }
    }
    return nullptr;
}

}  // namespace ndn
