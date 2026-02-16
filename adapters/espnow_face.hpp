/**
 * @file espnow_face.hpp
 * @brief ESP-NOW Face implementation
 *
 * NDN Face implementation using the ESP-NOW protocol.
 * Supports both broadcast and unicast.
 */

#pragma once

#include "ndn/face.hpp"

#include <array>
#include <cstring>

// Forward declaration for ESP-NOW types
extern "C" {
#include "esp_now.h"
}

namespace ndn {

/** @brief ESP-NOW maximum payload size (v2.0) */
constexpr size_t ESPNOW_MAX_PAYLOAD = 1470;

/** @brief ESP-NOW maximum number of peers */
constexpr size_t ESPNOW_MAX_PEERS = 20;

/** @brief Broadcast MAC address */
constexpr uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/**
 * @brief Generate FaceId from MAC address
 * @param mac MAC address (6 bytes)
 * @return FaceId
 */
inline FaceId macToFaceId(const uint8_t* mac) {
    // Use lower 2 bytes (offset by +2 since 0 is invalid)
    return static_cast<FaceId>(((mac[4] << 8) | mac[5]) + 2);
}

/**
 * @brief Peer information
 */
struct PeerInfo {
    uint8_t mac[6];     ///< MAC address
    FaceId faceId;      ///< Face ID
    bool inUse;         ///< In-use flag
    uint32_t lastSeen;  ///< Last received time (ms)
};

/**
 * @brief ESP-NOW Face
 *
 * Face implementation that sends/receives NDN packets using ESP-NOW protocol.
 *
 * Features:
 * - Broadcast transmission (broadcast)
 * - Unicast transmission (sendTo)
 * - Automatic peer discovery and management
 * - Maximum 250-byte payload (ESP-NOW v1.0 limit)
 *
 * @code
 * EspNowFace face;
 * face.setPacketCallback([](FaceId id, const uint8_t* data, size_t len) {
 *     // Handle received packet
 * });
 * face.start();
 * face.broadcast(packet, packetLen);
 * @endcode
 */
class EspNowFace : public Face {
public:
    /**
     * @brief Constructor
     * @param faceId ID of this Face (default: 2)
     */
    explicit EspNowFace(FaceId faceId = 2);

    /**
     * @brief Destructor
     */
    ~EspNowFace() override;

    /**
     * @brief Get Face ID
     * @return Face ID
     */
    FaceId id() const override { return faceId_; }

    /**
     * @brief Initialize and start ESP-NOW
     * @return Error::Success: success, Error::SendFailed: initialization failed
     *
     * Wi-Fi must be initialized beforehand.
     */
    Error start() override;

    /**
     * @brief Stop ESP-NOW
     */
    void stop() override;

    /**
     * @brief Default send (broadcast)
     * @param data Data to send
     * @param len Data length
     * @return Error::Success: success, Error::SendFailed: send failed,
     *         Error::BufferTooSmall: data too large
     */
    Error send(const uint8_t* data, size_t len) override;

    /**
     * @brief Unicast send to a specific Face
     * @param destFace Destination Face ID
     * @param data Data to send
     * @param len Data length
     * @return Error::Success: success, Error::NotFound: peer not registered,
     *         Error::SendFailed: send failed
     */
    Error sendTo(FaceId destFace, const uint8_t* data, size_t len) override;

    /**
     * @brief Broadcast send
     * @param data Data to send
     * @param len Data length
     * @return Error::Success: success, Error::SendFailed: send failed
     */
    Error broadcast(const uint8_t* data, size_t len) override;

    /**
     * @brief Get maximum payload size
     * @return Maximum payload size (250 bytes)
     */
    size_t maxPayloadSize() const override { return ESPNOW_MAX_PAYLOAD; }

    /**
     * @brief Add a peer
     * @param mac MAC address (6 bytes)
     * @return Added FaceId, FACE_ID_INVALID on failure
     */
    FaceId addPeer(const uint8_t* mac);

    /**
     * @brief Remove a peer
     * @param faceId Face ID to remove
     */
    void removePeer(FaceId faceId);

    /**
     * @brief Get MAC address from FaceId
     * @param faceId Face ID
     * @param mac [out] MAC address output (6 bytes)
     * @return true: success, false: peer not registered
     */
    bool getMacAddress(FaceId faceId, uint8_t* mac) const;

    /**
     * @brief Get number of registered peers
     * @return Number of peers
     */
    size_t peerCount() const;

    /**
     * @brief Process receive events
     *
     * Dequeues packets from the receive queue and invokes callbacks.
     * Must be called periodically from the main loop.
     */
    void processReceiveQueue();

    /**
     * @brief Set MAC address filter (single MAC)
     * @param mac Allowed MAC address (6 bytes), nullptr to disable filter
     *
     * When set, only packets from the specified MAC address are received.
     */
    void setMacFilter(const uint8_t* mac);

    /**
     * @brief Set multiple MAC address filters
     * @param macs Array of allowed MAC addresses (6 bytes each)
     * @param count Number of MAC addresses (max MAX_MAC_FILTERS)
     *
     * When set, only packets from the specified MAC addresses are received.
     * Used for topology control in multi-hop experiments.
     */
    void setMacFilters(const uint8_t macs[][6], size_t count);

    /**
     * @brief Clear MAC address filters
     */
    void clearMacFilters();

    /**
     * @brief Check if MAC address filter is enabled
     * @return true: filter enabled, false: filter disabled
     */
    bool hasMacFilter() const { return macFilterEnabled_; }

    /** @brief Maximum number of filter MACs */
    static constexpr size_t MAX_MAC_FILTERS = 4;

    /**
     * @brief Get the static instance (for callbacks)
     */
    static EspNowFace* instance() { return instance_; }

private:
    // ESP-NOW callbacks (forwarded from static to instance methods)
    static void onReceive(const esp_now_recv_info_t* info, const uint8_t* data, int len);
    static void onSend(const esp_now_send_info_t* info, esp_now_send_status_t status);

    // Receive handling
    void handleReceive(const uint8_t* srcMac, const uint8_t* data, size_t len);

    // Peer lookup
    PeerInfo* findPeer(FaceId faceId);
    PeerInfo* findPeerByMac(const uint8_t* mac);
    const PeerInfo* findPeer(FaceId faceId) const;

    FaceId faceId_;
    bool running_ = false;

    // Peer management
    std::array<PeerInfo, ESPNOW_MAX_PEERS> peers_{};

    // Receive queue (for safely passing data from ISR context)
    // Reduced from 16 to 8 for v2.0 large payload support (memory saving)
    static constexpr size_t RX_QUEUE_SIZE = 8;
    struct RxPacket {
        uint8_t srcMac[6];
        uint8_t data[ESPNOW_MAX_PAYLOAD];
        size_t len;
        bool valid;
    };
    std::array<RxPacket, RX_QUEUE_SIZE> rxQueue_{};
    volatile size_t rxQueueHead_ = 0;
    volatile size_t rxQueueTail_ = 0;

    // Static instance (for callbacks)
    static EspNowFace* instance_;

    // MAC address filters (multiple supported)
    uint8_t macFilters_[MAX_MAC_FILTERS][6] = {};
    size_t macFilterCount_ = 0;
    bool macFilterEnabled_ = false;
};

}  // namespace ndn
