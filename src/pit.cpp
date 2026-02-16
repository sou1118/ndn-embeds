#include "ndn/pit.hpp"

namespace ndn {

// =============================================================================
// PitEntry
// =============================================================================

FaceId PitEntry::face(size_t index) const {
    if (index >= numFaces_) {
        return FACE_ID_INVALID;
    }
    return incomingFaces_[index];
}

bool PitEntry::hasFace(FaceId faceId) const {
    for (size_t i = 0; i < numFaces_; ++i) {
        if (incomingFaces_[i] == faceId) {
            return true;
        }
    }
    return false;
}

bool PitEntry::addFace(FaceId faceId) {
    if (hasFace(faceId)) {
        return true;  // Already exists
    }
    if (numFaces_ >= PIT_MAX_FACES_PER_ENTRY) {
        return false;  // Full
    }
    incomingFaces_[numFaces_++] = faceId;
    return true;
}

// =============================================================================
// Pit
// =============================================================================

PitInsertResult Pit::insert(const Interest& interest, FaceId incomingFace, PitEntry** outEntry) {
    const Name& name = interest.name();
    const uint32_t nonce = interest.nonce().value_or(0);

    // Search for existing entry
    for (auto& entry : entries_) {
        if (entry.inUse_ && entry.name_.equals(name)) {
            // Check if same nonce (loop detection)
            if (entry.nonce_ == nonce) {
                stats_.duplicates++;
                if (outEntry != nullptr) {
                    *outEntry = &entry;
                }
                return PitInsertResult::Duplicate;
            }

            // Different nonce: add Face (aggregation)
            entry.addFace(incomingFace);
            stats_.aggregations++;
            if (outEntry != nullptr) {
                *outEntry = &entry;
            }
            return PitInsertResult::Aggregated;
        }
    }

    // Create new entry
    for (auto& entry : entries_) {
        if (!entry.inUse_) {
            entry.name_ = name;
            entry.nonce_ = nonce;
            entry.expireTime_ = currentTimeMs() + interest.lifetime();
            entry.numFaces_ = 0;
            entry.addFace(incomingFace);
            entry.inUse_ = true;
            size_++;
            stats_.insertions++;
            if (outEntry != nullptr) {
                *outEntry = &entry;
            }
            return PitInsertResult::New;
        }
    }

    // Table full
    return PitInsertResult::Full;
}

PitEntry* Pit::find(const Name& name) {
    for (auto& entry : entries_) {
        if (entry.inUse_ && entry.name_.equals(name)) {
            return &entry;
        }
    }
    return nullptr;
}

const PitEntry* Pit::find(const Name& name) const {
    for (const auto& entry : entries_) {
        if (entry.inUse_ && entry.name_.equals(name)) {
            return &entry;
        }
    }
    return nullptr;
}

void Pit::remove(PitEntry* entry) {
    if (entry != nullptr && entry->inUse_) {
        entry->inUse_ = false;
        entry->numFaces_ = 0;
        size_--;
    }
}

void Pit::remove(const Name& name) {
    PitEntry* entry = find(name);
    if (entry != nullptr) {
        remove(entry);
    }
}

void Pit::processTimeouts(TimeMs now, TimeoutCallback callback) {
    for (auto& entry : entries_) {
        if (entry.inUse_ && entry.expireTime_ <= now) {
            if (callback) {
                callback(entry);
            }
            entry.inUse_ = false;
            entry.numFaces_ = 0;
            size_--;
            stats_.timeouts++;
        }
    }
}

}  // namespace ndn
