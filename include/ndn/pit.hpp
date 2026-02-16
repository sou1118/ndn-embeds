/**
 * @file pit.hpp
 * @brief Pending Interest Table (PIT)
 *
 * The PIT is a table used by the forwarder to track received Interests.
 * When the same Name Interest is received from multiple Faces,
 * they are aggregated into a single entry.
 *
 * @see https://named-data.net/doc/NDN-packet-spec/current/
 */

#pragma once

#include "ndn/common.hpp"
#include "ndn/interest.hpp"
#include "ndn/name.hpp"
#include <functional>

namespace ndn {

/** @brief Maximum number of PIT entries */
constexpr size_t PIT_MAX_ENTRIES = 50;

/** @brief Maximum number of Faces per PIT entry */
constexpr size_t PIT_MAX_FACES_PER_ENTRY = 5;

/**
 * @brief PIT insertion result
 *
 * An enum representing the result of an Interest insertion.
 */
enum class PitInsertResult : uint8_t {
    New,         ///< New entry created
    Aggregated,  ///< Face added to existing entry (aggregation)
    Duplicate,   ///< Same nonce detected (loop)
    Full,        ///< Table is full
};

/**
 * @brief PIT entry
 *
 * Holds information about a single pending Interest.
 * When the same Interest is received from multiple Faces,
 * their Face IDs are recorded.
 */
class PitEntry {
public:
    /**
     * @brief Get the Interest Name
     * @return Const reference to the Name
     */
    const Name& name() const { return name_; }

    /**
     * @brief Get the Interest nonce
     * @return Nonce value
     */
    uint32_t nonce() const { return nonce_; }

    /**
     * @brief Get the entry expiration time
     * @return Expiration timestamp (milliseconds)
     */
    TimeMs expireTime() const { return expireTime_; }

    /** @name Face management
     * @{
     */

    /**
     * @brief Get the number of registered Faces
     * @return Number of Faces
     */
    size_t faceCount() const { return numFaces_; }

    /**
     * @brief Get the Face ID at a given index
     * @param index Index (starting from 0)
     * @return FaceId
     */
    FaceId face(size_t index) const;

    /**
     * @brief Check if a given Face is registered
     * @param faceId Face ID to check
     * @return true if registered
     */
    bool hasFace(FaceId faceId) const;

    /**
     * @brief Add a Face
     * @param faceId Face ID to add
     * @return true on success, false if already registered or full
     */
    bool addFace(FaceId faceId);
    /** @} */

private:
    friend class Pit;
    Name name_;                                                    ///< Interest Name
    uint32_t nonce_ = 0;                                           ///< Nonce for loop detection
    TimeMs expireTime_ = 0;                                        ///< Expiration time
    std::array<FaceId, PIT_MAX_FACES_PER_ENTRY> incomingFaces_{};  ///< Incoming Face list
    uint8_t numFaces_ = 0;                                         ///< Number of registered Faces
    bool inUse_ = false;                                           ///< Entry in-use flag
};

/**
 * @brief Pending Interest Table
 *
 * One of the core components of the forwarder.
 * Records received Interests and manages which Faces to forward
 * Data to when the corresponding Data arrives.
 *
 * @code
 * Pit pit;
 *
 * // Insert an Interest
 * PitEntry* entry;
 * auto result = pit.insert(interest, incomingFaceId, &entry);
 * if (result == PitInsertResult::New) {
 *     // New Interest -> forward
 * } else if (result == PitInsertResult::Aggregated) {
 *     // Existing Interest -> no forwarding needed
 * }
 *
 * // On Data reception
 * if (auto* entry = pit.find(dataName)) {
 *     // Forward Data to registered Faces
 *     for (size_t i = 0; i < entry->faceCount(); i++) {
 *         sendData(entry->face(i), data);
 *     }
 *     pit.remove(entry);
 * }
 * @endcode
 */
class Pit {
public:
    /** @name Interest management
     * @{
     */

    /**
     * @brief Insert an Interest
     *
     * If an entry with the same Name exists, aggregation is performed.
     * If the same nonce is detected, it is treated as a loop.
     *
     * @param interest Interest to insert
     * @param incomingFace ID of the Face that received the Interest
     * @param outEntry Stores a pointer to the created/updated entry (optional)
     * @return Insertion result
     */
    PitInsertResult insert(const Interest& interest, FaceId incomingFace,
                           PitEntry** outEntry = nullptr);

    /**
     * @brief Find an entry by Name
     * @param name Name to search for
     * @return Pointer to the entry if found, nullptr otherwise
     */
    PitEntry* find(const Name& name);

    /**
     * @brief Find an entry by Name (const version)
     * @param name Name to search for
     * @return Const pointer to the entry if found, nullptr otherwise
     */
    const PitEntry* find(const Name& name) const;

    /**
     * @brief Remove an entry
     * @param entry Pointer to the entry to remove
     */
    void remove(PitEntry* entry);

    /**
     * @brief Remove an entry by Name
     * @param name Name of the entry to remove
     */
    void remove(const Name& name);
    /** @} */

    /** @name Timeout handling
     * @{
     */

    /**
     * @brief Timeout callback
     *
     * Called when an entry times out.
     */
    using TimeoutCallback = std::function<void(const PitEntry&)>;

    /**
     * @brief Process timed-out entries
     *
     * Removes entries that have expired beyond the current time and invokes the callback.
     *
     * @param now Current time (milliseconds)
     * @param callback Timeout callback (optional)
     */
    void processTimeouts(TimeMs now, TimeoutCallback callback = nullptr);
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
    size_t capacity() const { return PIT_MAX_ENTRIES; }

    /**
     * @brief PIT statistics
     */
    struct Stats {
        uint32_t insertions = 0;    ///< Number of new insertions
        uint32_t aggregations = 0;  ///< Number of aggregations
        uint32_t duplicates = 0;    ///< Number of duplicate detections (loops)
        uint32_t timeouts = 0;      ///< Number of timeouts
    };

    /**
     * @brief Get statistics
     * @return Const reference to statistics
     */
    const Stats& stats() const { return stats_; }
    /** @} */

private:
    std::array<PitEntry, PIT_MAX_ENTRIES> entries_{};  ///< Entry array
    size_t size_ = 0;                                  ///< Number of entries in use
    Stats stats_{};                                    ///< Statistics
};

}  // namespace ndn
