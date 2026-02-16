#include "ndn/forwarder.hpp"
#include "ndn/tlv.hpp"

#include "esp_log.h"

namespace {
const char* TAG = "FWD";
}  // namespace

namespace ndn {

Forwarder::Forwarder() {
    for (auto& face : faces_) {
        face = nullptr;
    }
}

Error Forwarder::init(size_t csMaxEntries) {
    if (initialized_) {
        return Error::Success;
    }

    // Initialize Content Store
    const Error err = cs_.init(csMaxEntries);
    if (err != Error::Success) {
        ESP_LOGE(TAG, "Failed to initialize Content Store (size=%zu)", csMaxEntries);
        return err;
    }

    // Could add FIB routes for LocalFace (FaceId = 1) here
    // No special initialization needed at this point

    initialized_ = true;
    return Error::Success;
}

Error Forwarder::addFace(Face* face) {
    if (face == nullptr) {
        return Error::InvalidParam;
    }

    const FaceId newFaceId = face->id();
    if (newFaceId == FACE_ID_INVALID) {
        return Error::InvalidParam;
    }

    // Check for duplicates
    for (auto& f : faces_) {
        if (f != nullptr && f->id() == newFaceId) {
            return Error::InvalidParam;  // Duplicate
        }
    }

    // Find a free slot
    for (auto& f : faces_) {
        if (f == nullptr) {
            f = face;
            face->setPacketCallback([this](FaceId faceId, const uint8_t* data, size_t len) {
                onPacketReceived(faceId, data, len);
            });
            numFaces_++;
            return Error::Success;
        }
    }

    return Error::Full;
}

void Forwarder::removeFace(FaceId faceId) {
    for (auto& f : faces_) {
        if (f != nullptr && f->id() == faceId) {
            f->stop();
            f = nullptr;
            numFaces_--;
            fib_.removeFace(faceId);
            break;
        }
    }
}

Error Forwarder::expressInterest(const Interest& interest, DataCallback onData,
                                 TimeoutCallback onTimeout) {
    // Register pending Interest
    for (auto& pending : pendingInterests_) {
        if (!pending.inUse) {
            pending.interest = interest;
            pending.dataCallback = onData;
            pending.timeoutCallback = onTimeout;
            pending.inUse = true;

            // Insert into PIT
            PitEntry* entry = nullptr;
            auto result = pit_.insert(interest, FACE_ID_LOCAL, &entry);

            if (result == PitInsertResult::Full) {
                pending.inUse = false;
                return Error::Full;
            }

            // Forward
            forwardInterest(interest, FACE_ID_LOCAL);
            stats_.interestsSent++;
            return Error::Success;
        }
    }

    return Error::Full;
}

Error Forwarder::sendInterest(const Interest& interest) {
    // Forward only without PIT registration (e.g., Sync Interest)
    forwardInterest(interest, FACE_ID_LOCAL);
    stats_.interestsSent++;
    return Error::Success;
}

Error Forwarder::registerPrefix(const Name& prefix, InterestCallback callback) {
    for (auto& reg : prefixRegs_) {
        if (!reg.inUse) {
            reg.prefix = prefix;
            reg.callback = callback;
            reg.inUse = true;

            // Add route to LocalFace
            fib_.addRoute(prefix, FACE_ID_LOCAL, 0);
            return Error::Success;
        }
    }
    return Error::Full;
}

Error Forwarder::registerPrefix(std::string_view prefixUri, InterestCallback callback) {
    auto nameResult = Name::fromUri(prefixUri);
    if (!nameResult.ok()) {
        return nameResult.error;
    }
    return registerPrefix(nameResult.value, callback);
}

void Forwarder::unregisterPrefix(const Name& prefix) {
    for (auto& reg : prefixRegs_) {
        if (reg.inUse && reg.prefix.equals(prefix)) {
            reg.inUse = false;
            fib_.removeRoute(prefix, FACE_ID_LOCAL);
            break;
        }
    }
}

Error Forwarder::putData(const Data& data) {
    ESP_LOGI(TAG, "putData called");

    // Store in CS
    cs_.insert(data, currentTimeMs());

    // Match PIT and forward
    PitEntry* pitEntry = pit_.find(data.name());
    if (pitEntry != nullptr) {
        ESP_LOGI(TAG, "putData: PIT match found, forwarding to %zu faces", pitEntry->faceCount());
        forwardData(data, pitEntry);
        pit_.remove(pitEntry);
    } else {
        ESP_LOGW(TAG, "putData: no PIT match");
    }

    return Error::Success;
}

Error Forwarder::addRoute(const Name& prefix, FaceId faceId, uint8_t cost) {
    return fib_.addRoute(prefix, faceId, cost);
}

Error Forwarder::addRoute(std::string_view prefixUri, FaceId faceId, uint8_t cost) {
    auto nameResult = Name::fromUri(prefixUri);
    if (!nameResult.ok()) {
        return nameResult.error;
    }
    return fib_.addRoute(nameResult.value, faceId, cost);
}

void Forwarder::processEvents() {
    const TimeMs now = currentTimeMs();

    // PIT timeout processing
    pit_.processTimeouts(now, [this](const PitEntry& entry) {
        // Notify local application of timeout
        for (auto& pending : pendingInterests_) {
            if (pending.inUse && pending.interest.name().equals(entry.name())) {
                if (pending.timeoutCallback) {
                    pending.timeoutCallback(pending.interest);
                }
                pending.inUse = false;
                break;
            }
        }
    });

    // Evict stale CS entries (periodically)
    static TimeMs lastEviction = 0;
    if (now - lastEviction > 10000) {  // Every 10 seconds
        cs_.evictStale(now);
        lastEviction = now;
    }
}

void Forwarder::onPacketReceived(FaceId faceId, const uint8_t* data, size_t len) {
    if (len < 2) {
        return;
    }

    // Check TLV type
    uint32_t type = data[0];
    if (type == 253 && len >= 3) {
        type = (static_cast<uint32_t>(data[1]) << 8) | data[2];
    }

    if (type == tlv::Interest) {
        auto result = Interest::fromWire(data, len);
        if (result.ok()) {
            ESP_LOGI(TAG, "Interest received from face=%u", faceId);
            stats_.interestsReceived++;
            onInterestReceived(faceId, result.value);
        } else {
            ESP_LOGW(TAG, "Interest decode failed from face=%u, len=%zu", faceId, len);
        }
    } else if (type == tlv::Data) {
        auto result = Data::fromWire(data, len);
        if (result.ok()) {
            ESP_LOGI(TAG, "Data received from face=%u", faceId);
            stats_.dataReceived++;
            onDataReceived(faceId, result.value);
        }
    }
}

void Forwarder::onInterestReceived(FaceId faceId, const Interest& interest) {
    // 1. CS lookup (considering MustBeFresh flag)
    const CsEntry* csEntry = cs_.find(interest.name(), interest.mustBeFresh(), currentTimeMs());
    if (csEntry != nullptr) {
        // Cache hit: send Data back
        ESP_LOGI(TAG, "Cache hit for Interest, sending Data to face=%u", faceId);
        stats_.cacheHits++;
        uint8_t buf[PACKET_MAX_SIZE];
        size_t len = 0;
        if (csEntry->data().encode(buf, sizeof(buf), len) == Error::Success) {
            // Unicast reply to the originating peer
            for (auto& f : faces_) {
                if (f != nullptr) {
                    const Error err = f->sendTo(faceId, buf, len);
                    if (err == Error::Success) {
                        stats_.dataSent++;
                        ESP_LOGI(TAG, "Cache hit: Data sent to face=%u", faceId);
                        break;
                    }
                    // If NotFound, try the next Face
                }
            }
        }
        return;
    }
    stats_.cacheMisses++;

    // 2. PIT registration
    PitEntry* pitEntry = nullptr;
    auto pitResult = pit_.insert(interest, faceId, &pitEntry);

    if (pitResult == PitInsertResult::Duplicate) {
        // Loop detection - drop packet
        ESP_LOGI(TAG, "PIT: Duplicate Interest, dropping");
        return;
    }

    if (pitResult == PitInsertResult::Aggregated) {
        // Face already added to existing PIT entry - no need to re-forward
        ESP_LOGI(TAG, "PIT: Aggregated Interest");
        return;
    }

    // 3. Check local prefix registrations
    bool localHandled = false;
    char interestUri[128];
    interest.name().toUri(interestUri, sizeof(interestUri));

    for (auto& reg : prefixRegs_) {
        if (reg.inUse) {
            char prefixUri[128];
            reg.prefix.toUri(prefixUri, sizeof(prefixUri));
            const bool match = reg.prefix.isPrefixOf(interest.name());
            ESP_LOGI(TAG, "prefix check: interest=%s prefix=%s match=%d", interestUri, prefixUri,
                     match);
            if (match) {
                // Deliver to local application
                reg.callback(interest, faceId);
                localHandled = true;
                break;
            }
        }
    }

    // 4. FIB lookup and forward (only if not handled locally)
    //    If handled locally, Data will be returned via putData(), no need to forward
    if (!localHandled) {
        forwardInterest(interest, faceId);
    }
}

void Forwarder::onDataReceived(FaceId faceId, const Data& data) {
    // 1. PIT match
    PitEntry* pitEntry = pit_.find(data.name());
    if (pitEntry == nullptr) {
        // Unsolicited Data - drop
        return;
    }

    // 2. Store in CS
    cs_.insert(data, currentTimeMs());

    // 3. Callback to pending Interest
    for (auto& pending : pendingInterests_) {
        if (pending.inUse && pending.interest.name().equals(data.name())) {
            if (pending.dataCallback) {
                pending.dataCallback(data);
            }
            pending.inUse = false;
            break;
        }
    }

    // 4. Forward to other Faces
    forwardData(data, pitEntry);

    // 5. Remove PIT entry
    pit_.remove(pitEntry);
}

void Forwarder::forwardInterest(const Interest& interest, FaceId incomingFace) {
    const FibEntry* fibEntry = fib_.findLongestMatch(interest.name());
    if (fibEntry == nullptr || fibEntry->nexthopCount() == 0) {
        ESP_LOGW(TAG, "forwardInterest: no route");
        return;  // No route
    }

    char nameUri[64];
    interest.name().toUri(nameUri, sizeof(nameUri));
    ESP_LOGI(TAG, "forwardInterest: name=%s nexthops=%zu incoming=%u", nameUri,
             fibEntry->nexthopCount(), incomingFace);

    // Encode
    uint8_t buf[PACKET_MAX_SIZE];
    size_t len = 0;
    if (interest.encode(buf, sizeof(buf), len) != Error::Success) {
        ESP_LOGE(TAG, "forwardInterest: encode failed");
        return;
    }

    // Forward to each nexthop (except incoming)
    for (size_t i = 0; i < fibEntry->nexthopCount(); ++i) {
        const FaceId nextFace = fibEntry->nexthop(i).faceId;

        ESP_LOGI(TAG, "forwardInterest: nexthop[%zu]=%u", i, nextFace);

        if (nextFace == incomingFace || nextFace == FACE_ID_LOCAL) {
            ESP_LOGI(TAG, "forwardInterest: skipping (incoming or local)");
            continue;  // Do not send to incoming face or local
        }

        for (auto& f : faces_) {
            if (f != nullptr && f->id() == nextFace) {
                f->send(buf, len);
                ESP_LOGI(TAG, "forwardInterest: sent to face=%u len=%zu", nextFace, len);
                stats_.interestsSent++;
                break;
            }
        }
    }
}

void Forwarder::forwardData(const Data& data, PitEntry* pitEntry) {
    if (pitEntry == nullptr) {
        return;
    }

    // Encode
    uint8_t buf[PACKET_MAX_SIZE];
    size_t len = 0;
    if (data.encode(buf, sizeof(buf), len) != Error::Success) {
        ESP_LOGE(TAG, "forwardData: encode failed");
        return;
    }

    ESP_LOGI(TAG, "forwardData: sending to %zu faces", pitEntry->faceCount());

    // Send to each incoming face
    for (size_t i = 0; i < pitEntry->faceCount(); ++i) {
        const FaceId destFaceId = pitEntry->face(i);

        ESP_LOGI(TAG, "forwardData: face[%zu]=%u", i, destFaceId);

        if (destFaceId == FACE_ID_LOCAL) {
            ESP_LOGI(TAG, "forwardData: skipping local face");
            continue;  // Local face already handled separately
        }

        // FaceId recorded in PIT is the originating peer ID
        // Use sendTo() to unicast to that peer
        for (auto& f : faces_) {
            if (f != nullptr) {
                const Error err = f->sendTo(destFaceId, buf, len);
                if (err == Error::Success) {
                    ESP_LOGI(TAG, "forwardData: sent to face=%u", destFaceId);
                    stats_.dataSent++;
                    break;
                }
                // If NotFound, try the next Face
            }
        }
    }
}

}  // namespace ndn
