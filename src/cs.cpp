#include "ndn/cs.hpp"
#include "esp_heap_caps.h"
#include "esp_log.h"

namespace ndn {

namespace {
const char* TAG = "CS";
}  // namespace

// =============================================================================
// CsEntry
// =============================================================================

bool CsEntry::isFresh(TimeMs now) const {
    if (staleTime_ == 0) {
        return true;  // No FreshnessPeriod = always fresh
    }
    return now < staleTime_;
}

// =============================================================================
// ContentStore
// =============================================================================

ContentStore::~ContentStore() {
    if (entries_ != nullptr) {
        heap_caps_free(entries_);
        entries_ = nullptr;
    }
}

Error ContentStore::init(size_t maxEntries) {
    if (entries_ != nullptr) {
        ESP_LOGW(TAG, "Already initialized, skipping");
        return Error::Success;  // Already initialized is not an error
    }

    const size_t allocSize = sizeof(CsEntry) * maxEntries;
    entries_ =
        static_cast<CsEntry*>(heap_caps_malloc(allocSize, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));

    if (entries_ == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate %zu bytes from PSRAM for %zu entries", allocSize,
                 maxEntries);
        return Error::NoMemory;
    }

    capacity_ = maxEntries;
    size_ = 0;

    // Initialize all entries
    for (size_t i = 0; i < capacity_; i++) {
        entries_[i].inUse_ = false;
    }

    ESP_LOGI(TAG, "Initialized with %zu entries (%zu bytes PSRAM)", capacity_, allocSize);
    return Error::Success;
}

Error ContentStore::insert(const Data& data, TimeMs now) {
    const Name& name = data.name();

    // Search for existing entry (update)
    for (size_t i = 0; i < capacity_; i++) {
        auto& entry = entries_[i];
        if (entry.inUse_ && entry.data_.name().equals(name)) {
            entry.data_ = data;
            entry.lastUsed_ = now;
            if (data.freshnessPeriod()) {
                entry.staleTime_ = now + *data.freshnessPeriod();
            } else {
                entry.staleTime_ = 0;
            }
            return Error::Success;
        }
    }

    // Search for a free slot
    CsEntry* slot = nullptr;
    for (size_t i = 0; i < capacity_; i++) {
        if (!entries_[i].inUse_) {
            slot = &entries_[i];
            break;
        }
    }

    // If full, use LRU eviction
    if (slot == nullptr) {
        slot = findLruEntry();
        if (slot != nullptr) {
            stats_.evictions++;
            size_--;
        }
    }

    if (slot == nullptr) {
        return Error::Full;
    }

    slot->data_ = data;
    slot->lastUsed_ = now;
    if (data.freshnessPeriod()) {
        slot->staleTime_ = now + *data.freshnessPeriod();
    } else {
        slot->staleTime_ = 0;
    }
    slot->inUse_ = true;
    size_++;
    stats_.insertions++;

    return Error::Success;
}

const CsEntry* ContentStore::find(const Name& name, bool mustBeFresh, TimeMs now) const {
    for (size_t i = 0; i < capacity_; i++) {
        const auto& entry = entries_[i];
        if (entry.inUse_ && entry.data_.name().equals(name)) {
            if (mustBeFresh && !entry.isFresh(now)) {
                // Stale, do not count as cache hit
                const_cast<Stats&>(stats_).misses++;
                return nullptr;
            }
            const_cast<CsEntry&>(entry).lastUsed_ = now;
            const_cast<Stats&>(stats_).hits++;
            return &entry;
        }
    }
    const_cast<Stats&>(stats_).misses++;
    return nullptr;
}

void ContentStore::remove(const Name& name) {
    for (size_t i = 0; i < capacity_; i++) {
        auto& entry = entries_[i];
        if (entry.inUse_ && entry.data_.name().equals(name)) {
            entry.inUse_ = false;
            size_--;
            return;
        }
    }
}

void ContentStore::evictStale(TimeMs now) {
    for (size_t i = 0; i < capacity_; i++) {
        auto& entry = entries_[i];
        if (entry.inUse_ && !entry.isFresh(now)) {
            entry.inUse_ = false;
            size_--;
            stats_.evictions++;
        }
    }
}

CsEntry* ContentStore::findLruEntry() {
    CsEntry* lru = nullptr;
    TimeMs oldestTime = UINT64_MAX;

    for (size_t i = 0; i < capacity_; i++) {
        auto& entry = entries_[i];
        if (entry.inUse_ && entry.lastUsed_ < oldestTime) {
            oldestTime = entry.lastUsed_;
            lru = &entry;
        }
    }

    return lru;
}

}  // namespace ndn
