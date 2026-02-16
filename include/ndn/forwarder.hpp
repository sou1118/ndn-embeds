/**
 * @file forwarder.hpp
 * @brief NDN Forwarder
 *
 * The Forwarder is the central component of the NDN protocol stack.
 * It integrates PIT, CS, and FIB to forward Interest and Data packets.
 * It also provides application APIs for sending Interests and registering prefixes.
 *
 * @see https://named-data.net/doc/NFD/current/
 */

#pragma once

#include "ndn/common.hpp"
#include "ndn/cs.hpp"
#include "ndn/data.hpp"
#include "ndn/face.hpp"
#include "ndn/fib.hpp"
#include "ndn/interest.hpp"
#include "ndn/pit.hpp"

namespace ndn {

/**
 * @brief Interest receive callback
 *
 * Called when an Interest matching a registered prefix is received.
 *
 * @param interest Received Interest
 * @param faceId ID of the Face that received it
 */
using InterestCallback = std::function<void(const Interest&, FaceId)>;

/**
 * @brief Data receive callback
 *
 * Called when Data is received for an Interest sent via expressInterest().
 *
 * @param data Received Data
 */
using DataCallback = std::function<void(const Data&)>;

/**
 * @brief Timeout callback
 *
 * Called when an Interest sent via expressInterest() times out.
 *
 * @param interest Timed-out Interest
 */
using TimeoutCallback = std::function<void(const Interest&)>;

/** @brief Maximum number of Faces the Forwarder can manage */
constexpr size_t FORWARDER_MAX_FACES = 8;

/** @brief Maximum number of registerable prefixes */
constexpr size_t FORWARDER_MAX_PREFIXES = 16;

/**
 * @brief NDN Forwarder
 *
 * The central class responsible for NDN packet forwarding.
 * Provides the following features:
 * - Face management (add/remove)
 * - Interest/Data forwarding
 * - Application API (expressInterest, registerPrefix, putData)
 * - Integrated PIT, CS, and FIB management
 *
 * @code
 * // Initialize the Forwarder
 * Forwarder forwarder;
 * forwarder.init();
 *
 * // Add a Face
 * EspNowFace espNowFace;
 * forwarder.addFace(&espNowFace);
 *
 * // Register a prefix (producer)
 * forwarder.registerPrefix("/sensor", [&](const Interest& interest, FaceId face) {
 *     Data data;
 *     data.setName(interest.name());
 *     data.setContent("25.5 C");
 *     forwarder.putData(data);
 * });
 *
 * // Send an Interest (consumer)
 * Interest interest;
 * interest.setName("/sensor/temperature");
 * forwarder.expressInterest(interest, [](const Data& data) {
 *     printf("Received: %.*s\n", (int)data.contentSize(), data.content());
 * });
 *
 * // Event loop
 * while (true) {
 *     forwarder.processEvents();
 *     vTaskDelay(pdMS_TO_TICKS(10));
 * }
 * @endcode
 */
class Forwarder {
public:
    /**
     * @brief Constructor
     */
    Forwarder();

    /**
     * @brief Initialize the Forwarder
     *
     * Initializes the Content Store with the specified size.
     *
     * @param csMaxEntries Maximum number of Content Store entries (default: CS_DEFAULT_ENTRIES)
     * @return Error::Success on success, error code on CS initialization failure
     */
    Error init(size_t csMaxEntries = CS_DEFAULT_ENTRIES);

    /** @name Face management
     * @{
     */

    /**
     * @brief Add a Face
     *
     * @param face Pointer to the Face to add
     * @return Error::Success on success, Error::Full when at capacity
     */
    Error addFace(Face* face);

    /**
     * @brief Remove a Face
     *
     * Related next-hops are also removed from the FIB.
     *
     * @param faceId ID of the Face to remove
     */
    void removeFace(FaceId faceId);
    /** @} */

    /** @name Application API (consumer)
     * @{
     */

    /**
     * @brief Send an Interest and wait for Data
     *
     * Creates a PIT entry and forwards the Interest.
     * The onData callback is called when Data is received.
     * The onTimeout callback is called on timeout.
     *
     * @param interest Interest to send
     * @param onData Callback on Data reception
     * @param onTimeout Callback on timeout (optional)
     * @return Error::Success on success
     */
    Error expressInterest(const Interest& interest, DataCallback onData,
                          TimeoutCallback onTimeout = nullptr);

    /**
     * @brief Send an Interest (without PIT registration)
     *
     * Used when Data is not expected, such as for Sync Interests.
     *
     * @param interest Interest to send
     * @return Error::Success on success
     */
    Error sendInterest(const Interest& interest);
    /** @} */

    /** @name Application API (producer)
     * @{
     */

    /**
     * @brief Register a prefix
     *
     * The callback is called when an Interest matching the specified
     * prefix is received.
     *
     * @param prefix Name prefix to register
     * @param callback Callback on Interest reception
     * @return Error::Success on success, Error::Full when at capacity
     */
    Error registerPrefix(const Name& prefix, InterestCallback callback);

    /**
     * @brief Register a prefix (URI string version)
     *
     * @param prefixUri Prefix URI string
     * @param callback Callback on Interest reception
     * @return Error::Success on success
     */
    Error registerPrefix(std::string_view prefixUri, InterestCallback callback);

    /**
     * @brief Unregister a prefix
     * @param prefix Name prefix to unregister
     */
    void unregisterPrefix(const Name& prefix);

    /**
     * @brief Send Data
     *
     * Looks up the PIT entry and forwards Data to the matching Faces.
     * The Data is also stored in the cache.
     *
     * @param data Data to send
     * @return Error::Success on success
     */
    Error putData(const Data& data);
    /** @} */

    /** @name FIB route management
     * @{
     */

    /**
     * @brief Add a route
     *
     * @param prefix Name prefix
     * @param faceId Next-hop Face ID
     * @param cost Cost (default: 0)
     * @return Error::Success on success
     */
    Error addRoute(const Name& prefix, FaceId faceId, uint8_t cost = 0);

    /**
     * @brief Add a route (URI string version)
     *
     * @param prefixUri Prefix URI string
     * @param faceId Next-hop Face ID
     * @param cost Cost (default: 0)
     * @return Error::Success on success
     */
    Error addRoute(std::string_view prefixUri, FaceId faceId, uint8_t cost = 0);
    /** @} */

    /** @name Event processing
     * @{
     */

    /**
     * @brief Process events
     *
     * Performs timeout processing and other tasks.
     * Must be called periodically.
     */
    void processEvents();
    /** @} */

    /** @name Statistics
     * @{
     */

    /**
     * @brief Forwarder statistics
     */
    struct Stats {
        uint32_t interestsReceived = 0;  ///< Number of Interests received
        uint32_t interestsSent = 0;      ///< Number of Interests sent
        uint32_t dataReceived = 0;       ///< Number of Data received
        uint32_t dataSent = 0;           ///< Number of Data sent
        uint32_t cacheHits = 0;          ///< Number of cache hits
        uint32_t cacheMisses = 0;        ///< Number of cache misses
    };

    /**
     * @brief Get statistics
     * @return Const reference to statistics
     */
    const Stats& stats() const { return stats_; }
    /** @} */

    /** @name Access to internal components
     * @{
     */

    /**
     * @brief Get reference to PIT (for testing)
     * @return Reference to PIT
     */
    Pit& pit() { return pit_; }

    /**
     * @brief Get reference to Content Store (for testing)
     * @return Reference to ContentStore
     */
    ContentStore& cs() { return cs_; }

    /**
     * @brief Get reference to FIB (for testing)
     * @return Reference to FIB
     */
    Fib& fib() { return fib_; }
    /** @} */

private:
    /**
     * @brief Packet receive handler
     * @param faceId ID of the Face that received the packet
     * @param data Packet data
     * @param len Packet length
     */
    void onPacketReceived(FaceId faceId, const uint8_t* data, size_t len);

    /**
     * @brief Interest receive handler
     * @param faceId ID of the Face that received the Interest
     * @param interest Received Interest
     */
    void onInterestReceived(FaceId faceId, const Interest& interest);

    /**
     * @brief Data receive handler
     * @param faceId ID of the Face that received the Data
     * @param data Received Data
     */
    void onDataReceived(FaceId faceId, const Data& data);

    /**
     * @brief Forward an Interest
     * @param interest Interest to forward
     * @param incomingFace ID of the receiving Face (for loop prevention)
     */
    void forwardInterest(const Interest& interest, FaceId incomingFace);

    /**
     * @brief Forward Data
     * @param data Data to forward
     * @param pitEntry Corresponding PIT entry
     */
    void forwardData(const Data& data, PitEntry* pitEntry);

    Pit pit_;          ///< Pending Interest Table
    ContentStore cs_;  ///< Content Store
    Fib fib_;          ///< Forwarding Information Base

    std::array<Face*, FORWARDER_MAX_FACES> faces_{};  ///< Registered Faces
    size_t numFaces_ = 0;                             ///< Number of Faces

    /**
     * @brief Prefix registration information
     */
    struct PrefixRegistration {
        Name prefix;                ///< Registered prefix
        InterestCallback callback;  ///< Callback function
        bool inUse = false;         ///< In-use flag
    };
    std::array<PrefixRegistration, FORWARDER_MAX_PREFIXES> prefixRegs_{};  ///< Prefix registrations

    /**
     * @brief Pending Interest information (for application-level sends)
     */
    struct PendingInterest {
        Interest interest;                ///< Sent Interest
        DataCallback dataCallback;        ///< Data receive callback
        TimeoutCallback timeoutCallback;  ///< Timeout callback
        bool inUse = false;               ///< In-use flag
    };
    std::array<PendingInterest, PIT_MAX_ENTRIES> pendingInterests_{};  ///< Pending Interests

    Stats stats_{};             ///< Statistics
    bool initialized_ = false;  ///< Initialized flag
};

}  // namespace ndn
