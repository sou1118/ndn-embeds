#include "ndn/fib.hpp"

namespace ndn {

// =============================================================================
// FibEntry
// =============================================================================

namespace {
const FibNexthop INVALID_NEXTHOP{.faceId = FACE_ID_INVALID, .cost = 0};
}  // namespace

const FibNexthop& FibEntry::nexthop(size_t index) const {
    if (index >= numNexthops_) {
        return INVALID_NEXTHOP;
    }
    return nexthops_[index];
}

bool FibEntry::addNexthop(FaceId faceId, uint8_t cost) {
    // Update existing nexthop
    for (size_t i = 0; i < numNexthops_; ++i) {
        if (nexthops_[i].faceId == faceId) {
            nexthops_[i].cost = cost;
            return true;
        }
    }

    // Add new
    if (numNexthops_ >= FIB_MAX_NEXTHOPS) {
        return false;
    }

    nexthops_[numNexthops_].faceId = faceId;
    nexthops_[numNexthops_].cost = cost;
    numNexthops_++;
    return true;
}

bool FibEntry::removeNexthop(FaceId faceId) {
    for (size_t i = 0; i < numNexthops_; ++i) {
        if (nexthops_[i].faceId == faceId) {
            // Swap with last element and remove
            nexthops_[i] = nexthops_[numNexthops_ - 1];
            numNexthops_--;
            return true;
        }
    }
    return false;
}

// =============================================================================
// Fib
// =============================================================================

Error Fib::addRoute(const Name& prefix, FaceId faceId, uint8_t cost) {
    // Search for existing entry
    FibEntry* entry = findExact(prefix);
    if (entry != nullptr) {
        if (!entry->addNexthop(faceId, cost)) {
            return Error::Full;
        }
        return Error::Success;
    }

    // Create new entry
    for (auto& e : entries_) {
        if (!e.inUse_) {
            e.prefix_ = prefix;
            e.numNexthops_ = 0;
            e.addNexthop(faceId, cost);
            e.inUse_ = true;
            size_++;
            return Error::Success;
        }
    }

    return Error::Full;
}

void Fib::removeRoute(const Name& prefix, FaceId faceId) {
    FibEntry* entry = findExact(prefix);
    if (entry == nullptr) {
        return;
    }

    entry->removeNexthop(faceId);

    // Remove entry if no nexthops remain
    if (entry->numNexthops_ == 0) {
        entry->inUse_ = false;
        size_--;
    }
}

void Fib::removeRoute(const Name& prefix) {
    FibEntry* entry = findExact(prefix);
    if (entry != nullptr) {
        entry->inUse_ = false;
        entry->numNexthops_ = 0;
        size_--;
    }
}

void Fib::removeFace(FaceId faceId) {
    for (auto& entry : entries_) {
        if (entry.inUse_) {
            entry.removeNexthop(faceId);
            if (entry.numNexthops_ == 0) {
                entry.inUse_ = false;
                size_--;
            }
        }
    }
}

const FibEntry* Fib::findLongestMatch(const Name& name) const {
    const FibEntry* bestMatch = nullptr;
    size_t bestMatchLen = 0;

    for (const auto& entry : entries_) {
        if (entry.inUse_ && entry.prefix_.isPrefixOf(name)) {
            const size_t prefixLen = entry.prefix_.componentCount();
            if (prefixLen >= bestMatchLen) {
                bestMatch = &entry;
                bestMatchLen = prefixLen;
            }
        }
    }

    return bestMatch;
}

const FibEntry* Fib::findExact(const Name& prefix) const {
    for (const auto& entry : entries_) {
        if (entry.inUse_ && entry.prefix_.equals(prefix)) {
            return &entry;
        }
    }
    return nullptr;
}

FibEntry* Fib::findExact(const Name& prefix) {
    for (auto& entry : entries_) {
        if (entry.inUse_ && entry.prefix_.equals(prefix)) {
            return &entry;
        }
    }
    return nullptr;
}

}  // namespace ndn
