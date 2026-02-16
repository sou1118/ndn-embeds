/**
 * @file cs.hpp
 * @brief Content Store (CS)
 *
 * The Content Store caches received Data packets.
 * When an Interest with the same Name is received again,
 * Data can be returned from the cache without forwarding to the network.
 *
 * @see https://named-data.net/doc/NDN-packet-spec/current/
 */

#pragma once

#include "ndn/common.hpp"
#include "ndn/data.hpp"

namespace ndn {

/** @brief Default number of CS entries */
constexpr size_t CS_DEFAULT_ENTRIES = 15;

/** @brief Number of CS entries for MANET */
constexpr size_t CS_MANET_ENTRIES = 100;

/** @brief Number of CS entries for large-scale MANET */
constexpr size_t CS_LARGE_MANET_ENTRIES = 200;

/**
 * @brief Content Store entry
 *
 * Holds a single cached Data packet and its metadata.
 */
class CsEntry {
public:
    /**
     * @brief Get the cached Data
     * @return Const reference to the Data
     */
    const Data& data() const { return data_; }

    /**
     * @brief Get the freshness expiration timestamp
     *
     * After this time, the Data is considered "stale".
     *
     * @return Freshness expiration (milliseconds), 0 means no expiration
     */
    TimeMs staleTime() const { return staleTime_; }

    /**
     * @brief Check if the Data is fresh
     *
     * @param now Current time (milliseconds)
     * @return true if fresh
     */
    bool isFresh(TimeMs now) const;

private:
    friend class ContentStore;
    Data data_;             ///< Cached Data
    TimeMs staleTime_ = 0;  ///< Freshness expiration (0 = no expiration)
    TimeMs lastUsed_ = 0;   ///< Last access time (for LRU)
    bool inUse_ = false;    ///< Entry in-use flag
};

/**
 * @brief Content Store
 *
 * One of the core components of the forwarder.
 * Caches received Data and can respond to subsequent Interests
 * without forwarding to the network.
 *
 * Uses an LRU (Least Recently Used) replacement policy.
 *
 * @code
 * ContentStore cs;
 *
 * // Cache Data
 * Data data;
 * data.setName("/sensor/temperature");
 * data.setContent("25.5 C");
 * data.setFreshnessPeriod(10000);  // Valid for 10 seconds
 * cs.insert(data, currentTimeMs());
 *
 * // Search cache for Data
 * if (auto* entry = cs.find(interestName, mustBeFresh, now)) {
 *     // Cache hit
 *     sendData(entry->data());
 * }
 * @endcode
 */
class ContentStore {
public:
    /**
     * @brief Default constructor
     */
    ContentStore() = default;

    /**
     * @brief Destructor
     *
     * Frees memory allocated on PSRAM.
     */
    ~ContentStore();

    // Copy and move prohibited (due to pointer management)
    ContentStore(const ContentStore&) = delete;
    ContentStore& operator=(const ContentStore&) = delete;
    ContentStore(ContentStore&&) = delete;
    ContentStore& operator=(ContentStore&&) = delete;

    /**
     * @brief Initialize the Content Store
     *
     * Allocates the entry array on PSRAM.
     * This function must be called exactly once.
     *
     * @param maxEntries Maximum number of entries (default: CS_DEFAULT_ENTRIES)
     * @return Error::Success on success,
     *         Error::NoMemory on PSRAM allocation failure,
     *         Error::AlreadyExists if already initialized
     */
    Error init(size_t maxEntries = CS_DEFAULT_ENTRIES);

    /** @name Data management
     * @{
     */

    /**
     * @brief Insert Data into the cache
     *
     * Overwrites if an entry with the same Name exists.
     * If the cache is full, the oldest entry is evicted using the LRU policy.
     *
     * @param data Data to cache
     * @param now Current time (milliseconds)
     * @return Error::Success on success
     */
    Error insert(const Data& data, TimeMs now);

    /**
     * @brief Search the cache by Name
     *
     * @param name Name to search for
     * @param mustBeFresh If true, only return fresh Data
     * @param now Current time (used when mustBeFresh=true)
     * @return Pointer to the entry if found, nullptr otherwise
     */
    const CsEntry* find(const Name& name, bool mustBeFresh = false, TimeMs now = 0) const;

    /**
     * @brief Remove the entry with the specified Name
     * @param name Name of the entry to remove
     */
    void remove(const Name& name);

    /**
     * @brief Remove stale entries
     *
     * Removes all entries that have exceeded their staleTime.
     *
     * @param now Current time (milliseconds)
     */
    void evictStale(TimeMs now);
    /** @} */

    /** @name Statistics
     * @{
     */

    /**
     * @brief Get the current number of entries
     * @return Number of entries
     */
    size_t size() const { return size_; }

    /**
     * @brief Get the maximum number of entries
     * @return Maximum number of entries
     */
    size_t capacity() const { return capacity_; }

    /**
     * @brief CS statistics
     */
    struct Stats {
        uint32_t hits = 0;        ///< Cache hit count
        uint32_t misses = 0;      ///< Cache miss count
        uint32_t insertions = 0;  ///< Insertion count
        uint32_t evictions = 0;   ///< Eviction count
    };

    /**
     * @brief Get statistics
     * @return Const reference to statistics
     */
    const Stats& stats() const { return stats_; }
    /** @} */

private:
    CsEntry* entries_ = nullptr;  ///< Entry array (on PSRAM)
    size_t capacity_ = 0;         ///< Maximum number of entries
    size_t size_ = 0;             ///< Number of entries in use
    Stats stats_{};               ///< Statistics

    /**
     * @brief Find the oldest entry for LRU replacement
     * @return Pointer to the entry with the oldest lastUsed
     */
    CsEntry* findLruEntry();
};

}  // namespace ndn
