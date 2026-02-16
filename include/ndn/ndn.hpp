/**
 * @file ndn.hpp
 * @brief NDN Protocol Stack for ESP32 - Main include file
 *
 * The main header file for using the NDN protocol stack.
 * Including this file provides access to all public APIs.
 *
 * Also provides a global Forwarder instance and convenience APIs.
 *
 * @code
 * #include <ndn/ndn.hpp>
 *
 * void app_main() {
 *     // Initialize NDN
 *     ndn::initialize();
 *
 *     // Send an Interest using the convenience API
 *     ndn::Interest interest;
 *     interest.setName("/sensor/temperature");
 *     ndn::expressInterest(interest, [](const ndn::Data& data) {
 *         // Handle received Data
 *     });
 *
 *     // Event loop
 *     while (true) {
 *         ndn::processEvents();
 *         vTaskDelay(pdMS_TO_TICKS(10));
 *     }
 * }
 * @endcode
 */

#pragma once

#include "ndn/certificate.hpp"
#include "ndn/common.hpp"
#include "ndn/crypto.hpp"
#include "ndn/cs.hpp"
#include "ndn/data.hpp"
#include "ndn/face.hpp"
#include "ndn/fib.hpp"
#include "ndn/forwarder.hpp"
#include "ndn/interest.hpp"
#include "ndn/link.hpp"
#include "ndn/name.hpp"
#include "ndn/pit.hpp"
#include "ndn/signature.hpp"
#include "ndn/tlv.hpp"

namespace ndn {

/**
 * @brief Get the global Forwarder instance
 *
 * Provides a Forwarder instance using the singleton pattern.
 * Use after calling initialize().
 *
 * @return Reference to the global Forwarder
 */
Forwarder& getForwarder();

/**
 * @brief Initialize the NDN protocol stack
 *
 * Initializes the global Forwarder.
 * Must be called before using other NDN APIs.
 *
 * @return Error::Success on success
 */
Error initialize();

/** @name Convenience API
 *
 * Helper functions that use the global Forwarder.
 * Can be used when a single Forwarder is sufficient.
 * @{
 */

/**
 * @brief Send an Interest and wait for Data
 *
 * @param interest Interest to send
 * @param onData Callback on Data reception
 * @param onTimeout Callback on timeout (optional)
 * @return Error::Success on success
 *
 * @see Forwarder::expressInterest()
 */
inline Error expressInterest(const Interest& interest, DataCallback onData,
                             TimeoutCallback onTimeout = nullptr) {
    return getForwarder().expressInterest(interest, onData, onTimeout);
}

/**
 * @brief Register a prefix
 *
 * @param prefix Prefix URI string
 * @param callback Callback on Interest reception
 * @return Error::Success on success
 *
 * @see Forwarder::registerPrefix()
 */
inline Error registerPrefix(std::string_view prefix, InterestCallback callback) {
    return getForwarder().registerPrefix(prefix, callback);
}

/**
 * @brief Send Data
 *
 * @param data Data to send
 * @return Error::Success on success
 *
 * @see Forwarder::putData()
 */
inline Error putData(const Data& data) {
    return getForwarder().putData(data);
}

/**
 * @brief Process events
 *
 * Must be called periodically.
 *
 * @see Forwarder::processEvents()
 */
inline void processEvents() {
    getForwarder().processEvents();
}
/** @} */

}  // namespace ndn
