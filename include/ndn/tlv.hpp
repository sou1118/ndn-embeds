/**
 * @file tlv.hpp
 * @brief NDN TLV (Type-Length-Value) encoding
 *
 * Provides classes and utility functions for encoding/decoding
 * NDN packets in TLV format.
 *
 * @see https://docs.named-data.net/NDN-packet-spec/current/tlv.html
 */

#pragma once

#include "ndn/common.hpp"

namespace ndn {

/**
 * @brief TLV Type number definitions
 *
 * Standard TLV Type numbers used in NDN packets.
 */
namespace tlv {

/** @name Packet types
 * @{
 */
constexpr uint32_t Interest = 0x05;  ///< Interest packet
constexpr uint32_t Data = 0x06;      ///< Data packet
/** @} */

/** @name Common fields
 * @{
 */
constexpr uint32_t Name = 0x07;  ///< Name
/** @} */

/** @name Name components
 * @{
 */
constexpr uint32_t GenericNameComponent = 0x08;    ///< Generic Name component
constexpr uint32_t ImplicitSha256Digest = 0x01;    ///< Implicit SHA-256 digest
constexpr uint32_t ParametersSha256Digest = 0x02;  ///< Parameters SHA-256 digest
/** @} */

/** @name Interest packet fields
 * @{
 */
constexpr uint32_t CanBePrefix = 0x21;            ///< CanBePrefix flag
constexpr uint32_t MustBeFresh = 0x12;            ///< MustBeFresh flag
constexpr uint32_t ForwardingHint = 0x1e;         ///< Forwarding hint
constexpr uint32_t Nonce = 0x0a;                  ///< Nonce (for loop detection)
constexpr uint32_t InterestLifetime = 0x0c;       ///< Interest lifetime
constexpr uint32_t HopLimit = 0x22;               ///< Hop limit
constexpr uint32_t ApplicationParameters = 0x24;  ///< Application parameters
/** @} */

/** @name Data packet fields
 * @{
 */
constexpr uint32_t MetaInfo = 0x14;        ///< Meta information
constexpr uint32_t Content = 0x15;         ///< Content
constexpr uint32_t SignatureInfo = 0x16;   ///< Signature info
constexpr uint32_t SignatureValue = 0x17;  ///< Signature value
/** @} */

/** @name MetaInfo fields
 * @{
 */
constexpr uint32_t ContentType = 0x18;      ///< Content type
constexpr uint32_t FreshnessPeriod = 0x19;  ///< Freshness period
constexpr uint32_t FinalBlockId = 0x1a;     ///< Final block ID
/** @} */

/** @name SignatureInfo sub-fields
 * @{
 */
constexpr uint32_t SignatureType = 0x1b;  ///< Signature type
constexpr uint32_t KeyLocator = 0x1c;     ///< Key locator
constexpr uint32_t KeyDigest = 0x1d;      ///< Key digest
/** @} */

/** @name Interest signature fields (for future use)
 * @{
 */
constexpr uint32_t SignatureNonce = 0x26;          ///< Signature nonce
constexpr uint32_t SignatureTime = 0x28;           ///< Signature timestamp
constexpr uint32_t SignatureSeqNum = 0x2a;         ///< Signature sequence number
constexpr uint32_t InterestSignatureInfo = 0x2c;   ///< Interest signature info
constexpr uint32_t InterestSignatureValue = 0x2e;  ///< Interest signature value
/** @} */

/** @name Certificate-related fields
 * @{
 */
constexpr uint32_t ValidityPeriod = 0xfd;  ///< Validity period (253)
constexpr uint32_t NotBefore = 0xfe;       ///< Not before (254)
constexpr uint32_t NotAfter = 0xff;        ///< Not after (255)
/** @} */

}  // namespace tlv

/**
 * @brief TLV encoder
 *
 * A class for writing data to a buffer in TLV format.
 *
 * @code
 * uint8_t buffer[64];
 * TlvEncoder encoder(buffer, sizeof(buffer));
 *
 * encoder.writeType(tlv::Name);
 * encoder.writeLength(5);
 * encoder.writeBytes(data, 5);
 * @endcode
 */
class TlvEncoder {
public:
    /**
     * @brief Constructor
     * @param buf Pointer to the output buffer
     * @param capacity Buffer capacity (bytes)
     */
    TlvEncoder(uint8_t* buf, size_t capacity);

    /**
     * @brief Write a value in VAR-NUMBER format
     *
     * Encodes in NDN specification VAR-NUMBER format:
     * - 0-252: 1 byte
     * - 253-65535: 0xFD + 2 bytes (big-endian)
     * - 65536-4294967295: 0xFE + 4 bytes (big-endian)
     * - Larger: 0xFF + 8 bytes (big-endian)
     *
     * @param value Value to write
     * @return Error::Success on success, Error::BufferTooSmall if buffer is insufficient
     */
    Error writeVarNumber(uint64_t value);

    /**
     * @brief Write a non-negative integer (big-endian, minimum bytes)
     * @param value Value to write
     * @return Error::Success on success
     */
    Error writeNonNegativeInteger(uint64_t value);

    /**
     * @brief Write a TLV Type
     * @param type Type number
     * @return Error::Success on success
     */
    Error writeType(uint32_t type);

    /**
     * @brief Write a TLV Length
     * @param length Length value
     * @return Error::Success on success
     */
    Error writeLength(size_t length);

    /**
     * @brief Write a byte sequence
     * @param data Pointer to data
     * @param len Data length
     * @return Error::Success on success
     */
    Error writeBytes(const uint8_t* data, size_t len);

    /**
     * @brief Write a complete TLV structure
     * @param type Type number
     * @param value Pointer to the Value data
     * @param valueLen Length of the Value
     * @return Error::Success on success
     */
    Error writeTlv(uint32_t type, const uint8_t* value, size_t valueLen);

    /**
     * @brief Write a non-negative integer as a TLV
     * @param type Type number
     * @param value Value
     * @return Error::Success on success
     */
    Error writeTlvNonNegativeInteger(uint32_t type, uint64_t value);

    /**
     * @brief Current write position (= number of bytes written)
     * @return Number of bytes written
     */
    size_t size() const { return pos_; }

    /**
     * @brief Remaining writable bytes
     * @return Number of remaining bytes
     */
    size_t remaining() const { return capacity_ - pos_; }

    /**
     * @brief Pointer to current position
     * @return Pointer to the current write position
     */
    uint8_t* current() { return buf_ + pos_; }

    /**
     * @brief Get current position
     * @return Current position offset
     */
    size_t position() const { return pos_; }

    /**
     * @brief Set current position
     * @param pos New position
     */
    void setPosition(size_t pos) { pos_ = pos; }

private:
    uint8_t* buf_;     ///< Output buffer
    size_t capacity_;  ///< Buffer capacity
    size_t pos_ = 0;   ///< Current position
};

/**
 * @brief TLV decoder
 *
 * A class for reading TLV-formatted data from a buffer.
 *
 * @code
 * TlvDecoder decoder(buffer, length);
 *
 * auto header = decoder.readTlvHeader();
 * if (header.ok()) {
 *     printf("Type: %u, Length: %zu\n", header.value.type, header.value.length);
 * }
 * @endcode
 */
class TlvDecoder {
public:
    /**
     * @brief Constructor
     * @param buf Pointer to the input buffer
     * @param len Buffer length
     */
    TlvDecoder(const uint8_t* buf, size_t len);

    /**
     * @brief Read a value in VAR-NUMBER format
     * @return Value and Error::Success on success, Error::DecodeFailed on failure
     */
    Result<uint64_t> readVarNumber();

    /**
     * @brief Read a non-negative integer of specified byte count
     * @param numBytes Number of bytes to read (1, 2, 4, or 8)
     * @return Value and Error::Success on success
     */
    Result<uint64_t> readNonNegativeInteger(size_t numBytes);

    /**
     * @brief Read a TLV Type
     * @return Type number and Error::Success on success
     */
    Result<uint32_t> readType();

    /**
     * @brief Read a TLV Length
     * @return Length value and Error::Success on success
     */
    Result<size_t> readLength();

    /**
     * @brief TLV header information
     */
    struct TlvHeader {
        uint32_t type;  ///< Type number
        size_t length;  ///< Length value
    };

    /**
     * @brief Read a TLV header (Type and Length) at once
     * @return TlvHeader and Error::Success on success
     */
    Result<TlvHeader> readTlvHeader();

    /**
     * @brief Read a specified number of bytes
     * @param out Output buffer
     * @param len Number of bytes to read
     * @return Error::Success on success
     */
    Error readBytes(uint8_t* out, size_t len);

    /**
     * @brief Skip a specified number of bytes
     * @param len Number of bytes to skip
     * @return Error::Success on success
     */
    Error skip(size_t len);

    /**
     * @brief Remaining readable bytes
     * @return Number of remaining bytes
     */
    size_t remaining() const { return len_ - pos_; }

    /**
     * @brief Pointer to current position
     * @return Pointer to the current read position
     */
    const uint8_t* current() const { return buf_ + pos_; }

    /**
     * @brief Check if there is more data
     * @return true if data remains
     */
    bool hasMore() const { return pos_ < len_; }

    /**
     * @brief Get current position
     * @return Current position offset
     */
    size_t position() const { return pos_; }

    /**
     * @brief Set current position
     * @param pos New position
     */
    void setPosition(size_t pos) { pos_ = pos; }

private:
    const uint8_t* buf_;  ///< Input buffer
    size_t len_;          ///< Buffer length
    size_t pos_ = 0;      ///< Current position
};

/**
 * @brief Calculate the encoded size of a VAR-NUMBER
 * @param value Value
 * @return Encoded size in bytes
 */
constexpr size_t varNumberSize(uint64_t value) {
    if (value <= 252) {
        return 1;
    }
    if (value <= 0xFFFF) {
        return 3;
    }
    if (value <= 0xFFFFFFFF) {
        return 5;
    }
    return 9;
}

/**
 * @brief Calculate the encoded size of a non-negative integer (minimum bytes)
 * @param value Value
 * @return Encoded size in bytes (1, 2, 4, or 8)
 */
constexpr size_t nonNegativeIntegerSize(uint64_t value) {
    if (value <= 0xFF) {
        return 1;
    }
    if (value <= 0xFFFF) {
        return 2;
    }
    if (value <= 0xFFFFFFFF) {
        return 4;
    }
    return 8;
}

}  // namespace ndn
