/**
 * @file fib.hpp
 * @brief Forwarding Information Base (FIB)
 *
 * The FIB is a routing table used to determine where to forward Interests.
 * Each entry holds a Name prefix and a list of next-hop Faces
 * corresponding to that prefix.
 *
 * @see https://named-data.net/doc/NFD/current/
 */

#pragma once

#include "ndn/common.hpp"
#include "ndn/name.hpp"

namespace ndn {

/** @brief Maximum number of FIB entries */
constexpr size_t FIB_MAX_ENTRIES = 30;

/** @brief Maximum number of next-hops per FIB entry */
constexpr size_t FIB_MAX_NEXTHOPS = 3;

/**
 * @brief FIB Nexthop
 *
 * A structure holding the next-hop Face and its cost (priority).
 */
struct FibNexthop {
    FaceId faceId = FACE_ID_INVALID;  ///< Next-hop Face ID
    uint8_t cost = 0;                 ///< Cost (lower is preferred)
};

/**
 * @brief FIB entry
 *
 * Holds forwarding information for a single Name prefix.
 * Can have multiple next-hops, supporting multipath forwarding.
 */
class FibEntry {
public:
    /**
     * @brief Get the Name prefix
     * @return Const reference to the Name
     */
    const Name& prefix() const { return prefix_; }

    /** @name Nexthop management
     * @{
     */

    /**
     * @brief Get the number of next-hops
     * @return Number of next-hops
     */
    size_t nexthopCount() const { return numNexthops_; }

    /**
     * @brief Get the next-hop at a given index
     * @param index Index (starting from 0)
     * @return Const reference to FibNexthop
     */
    const FibNexthop& nexthop(size_t index) const;

    /**
     * @brief Add a next-hop
     *
     * If the same Face is already registered, updates its cost.
     *
     * @param faceId Face ID to add
     * @param cost Cost (default: 0)
     * @return true on success, false if full
     */
    bool addNexthop(FaceId faceId, uint8_t cost = 0);

    /**
     * @brief Remove a next-hop
     * @param faceId Face ID to remove
     * @return true on success, false if not found
     */
    bool removeNexthop(FaceId faceId);
    /** @} */

private:
    friend class Fib;
    Name prefix_;                                          ///< Name prefix
    std::array<FibNexthop, FIB_MAX_NEXTHOPS> nexthops_{};  ///< Nexthop list
    uint8_t numNexthops_ = 0;                              ///< Number of registered next-hops
    bool inUse_ = false;                                   ///< Entry in-use flag
};

/**
 * @brief Forwarding Information Base
 *
 * One of the core components of the forwarder.
 * Determines which Face to forward Interests to.
 * Uses Longest Prefix Match for forwarding lookups.
 *
 * @code
 * Fib fib;
 *
 * // Add a route
 * Name prefix;
 * prefix.appendComponent("sensor");
 * fib.addRoute(prefix, espNowFaceId, 10);  // Cost 10
 *
 * // Look up forwarding destination (Longest Prefix Match)
 * Name interestName;
 * interestName.appendComponent("sensor");
 * interestName.appendComponent("temperature");
 * if (auto* entry = fib.findLongestMatch(interestName)) {
 *     for (size_t i = 0; i < entry->nexthopCount(); i++) {
 *         forwardTo(entry->nexthop(i).faceId, interest);
 *     }
 * }
 * @endcode
 */
class Fib {
public:
    /** @name Route management
     * @{
     */

    /**
     * @brief Add a route
     *
     * Registers a forwarding destination for the specified prefix.
     * If the prefix already exists, adds a next-hop.
     *
     * @param prefix Name prefix
     * @param faceId Next-hop Face ID
     * @param cost Cost (default: 0)
     * @return Error::Success on success, Error::Full when table is full
     */
    Error addRoute(const Name& prefix, FaceId faceId, uint8_t cost = 0);

    /**
     * @brief Remove a specific next-hop
     * @param prefix Name prefix
     * @param faceId Face ID to remove
     */
    void removeRoute(const Name& prefix, FaceId faceId);

    /**
     * @brief Remove all routes for a prefix
     * @param prefix Name prefix
     */
    void removeRoute(const Name& prefix);

    /**
     * @brief Remove a specified Face from all entries
     *
     * Call this when a Face is disconnected.
     *
     * @param faceId Face ID to remove
     */
    void removeFace(FaceId faceId);
    /** @} */

    /** @name Lookup
     * @{
     */

    /**
     * @brief Look up using Longest Prefix Match
     *
     * Returns the entry with the longest prefix that matches
     * the given Name.
     *
     * @param name Name to search for
     * @return Pointer to the entry if found, nullptr otherwise
     */
    const FibEntry* findLongestMatch(const Name& name) const;

    /**
     * @brief Look up using exact match
     * @param prefix Prefix to search for
     * @return Const pointer to the entry if found, nullptr otherwise
     */
    const FibEntry* findExact(const Name& prefix) const;

    /**
     * @brief Look up using exact match (non-const version)
     * @param prefix Prefix to search for
     * @return Pointer to the entry if found, nullptr otherwise
     */
    FibEntry* findExact(const Name& prefix);
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
    size_t capacity() const { return FIB_MAX_ENTRIES; }
    /** @} */

private:
    std::array<FibEntry, FIB_MAX_ENTRIES> entries_{};  ///< Entry array
    size_t size_ = 0;                                  ///< Number of entries in use
};

}  // namespace ndn
