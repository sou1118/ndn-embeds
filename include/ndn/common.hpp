/**
 * @file common.hpp
 * @brief Common definitions for the NDN protocol stack
 *
 * Provides fundamental types and definitions used throughout the NDN library,
 * including error codes, constants, and the Result type.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace ndn {

/**
 * @brief Error codes
 *
 * Represents errors that may occur in NDN library operations.
 */
enum class Error : uint8_t {
    Success = 0,        ///< Success
    InvalidParam,       ///< Invalid parameter
    BufferTooSmall,     ///< Buffer too small
    DecodeFailed,       ///< Decode failed
    NotFound,           ///< Not found
    NoMemory,           ///< Out of memory
    Full,               ///< Table is full
    Timeout,            ///< Timeout
    SendFailed,         ///< Send failed
    InvalidPacket,      ///< Invalid packet
    NameTooLong,        ///< Name is too long
    TooManyComponents,  ///< Too many components
};

/**
 * @brief Convert error code to string
 * @param error Error code
 * @return String representation of the error
 */
constexpr const char* errorToString(Error error) {
    switch (error) {
        case Error::Success:
            return "Success";
        case Error::InvalidParam:
            return "InvalidParam";
        case Error::BufferTooSmall:
            return "BufferTooSmall";
        case Error::DecodeFailed:
            return "DecodeFailed";
        case Error::NotFound:
            return "NotFound";
        case Error::NoMemory:
            return "NoMemory";
        case Error::Full:
            return "Full";
        case Error::Timeout:
            return "Timeout";
        case Error::SendFailed:
            return "SendFailed";
        case Error::InvalidPacket:
            return "InvalidPacket";
        case Error::NameTooLong:
            return "NameTooLong";
        case Error::TooManyComponents:
            return "TooManyComponents";
        default:
            return "Unknown";
    }
}

/**
 * @brief Content type
 *
 * Represents the content type of a Data packet.
 * @see https://docs.named-data.net/NDN-packet-spec/current/types.html
 */
enum class ContentType : uint8_t {
    Blob = 0,  ///< Binary data (default)
    Link = 1,  ///< Link Object (list of Names for forwarding hints)
    Key = 2,   ///< Public key
    Nack = 3,  ///< Network NACK
};

/** @brief Maximum number of Names in a Link */
constexpr size_t LINK_MAX_DELEGATIONS = 5;

/**
 * @brief Face identifier
 *
 * A 16-bit integer that uniquely identifies each Face.
 */
using FaceId = uint16_t;

/** @brief Invalid Face ID */
constexpr FaceId FACE_ID_INVALID = 0;

/** @brief Face ID for local application */
constexpr FaceId FACE_ID_LOCAL = 1;

/**
 * @brief Timestamp type (milliseconds)
 */
using TimeMs = uint64_t;

/** @brief Maximum Name length (bytes) */
constexpr size_t NAME_MAX_LENGTH = 128;

/** @brief Maximum number of Name components */
constexpr size_t NAME_MAX_COMPONENTS = 10;

/** @brief Maximum content size of a Data packet (bytes)
 *  ESP-NOW v2.0: max 1470 bytes - TLV overhead (approx. 30-40 bytes)
 *  Measured: max 1434 bytes with /ndn/ping/<seq>
 */
constexpr size_t DATA_MAX_CONTENT_SIZE = 1440;

/** @brief Maximum packet size (ESP-NOW v2.0 compatible) */
constexpr size_t PACKET_MAX_SIZE = 1470;

/** @brief Default Interest lifetime (milliseconds) */
constexpr uint32_t INTEREST_DEFAULT_LIFETIME_MS = 4000;

/**
 * @brief Result type template
 *
 * A type for returning both a value and an error code without using exceptions.
 *
 * @tparam T Type of the value returned on success
 *
 * @code
 * Result<int> divide(int a, int b) {
 *     if (b == 0) return {0, Error::InvalidParam};
 *     return {a / b, Error::Success};
 * }
 *
 * auto result = divide(10, 2);
 * if (result.ok()) {
 *     printf("Result: %d\n", result.value);
 * }
 * @endcode
 */
template <typename T>
struct Result {
    T value;      ///< Result value
    Error error;  ///< Error code

    /**
     * @brief Check if the operation succeeded
     * @return true if successful
     */
    bool ok() const { return error == Error::Success; }

    /**
     * @brief Implicit conversion to bool
     * @return true if successful
     */
    explicit operator bool() const { return ok(); }
};

/**
 * @brief Get current time (milliseconds)
 * @return Elapsed time since boot (milliseconds)
 */
TimeMs currentTimeMs();

/**
 * @brief Generate a random Nonce value
 * @return 32-bit random value
 */
uint32_t generateRandomNonce();

}  // namespace ndn
