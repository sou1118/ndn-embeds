/**
 * @file name.hpp
 * @brief NDN Name class
 *
 * Provides a class representing NDN Names.
 * A Name consists of multiple NameComponents and enables hierarchical data naming.
 *
 * @see https://docs.named-data.net/NDN-packet-spec/current/name.html
 */

#pragma once

#include "ndn/common.hpp"

namespace ndn {

/**
 * @brief Name component
 *
 * A structure representing an individual component of a Name.
 * Holds a pointer to and size of the component data in the buffer.
 *
 * @note This pointer references the original Name buffer and becomes
 *       invalid when the Name is destroyed.
 */
struct NameComponent {
    const uint8_t* value;  ///< Pointer to the component value
    size_t size;           ///< Size of the component in bytes

    /**
     * @brief Get the component as a string view
     * @return string_view of the component value
     */
    std::string_view asString() const {
        return std::string_view(reinterpret_cast<const char*>(value), size);
    }
};

/**
 * @brief NDN Name class
 *
 * A class representing the name of an NDN packet. A name consists of multiple
 * components and can be expressed in URI format (e.g., "/sensor/temperature").
 *
 * @code
 * // Create a Name from a URI string
 * auto result = ndn::Name::fromUri("/sensor/temperature");
 * if (result.ok()) {
 *     Name& name = result.value;
 *     printf("Components: %zu\n", name.componentCount());
 *
 *     // Output in URI format
 *     char uri[64];
 *     name.toUri(uri, sizeof(uri));
 *     printf("URI: %s\n", uri);
 * }
 *
 * // Append components
 * Name name;
 * name.appendComponent("test");
 * name.appendComponent("data");
 * @endcode
 */
class Name {
public:
    /**
     * @brief Default constructor
     *
     * Creates an empty Name.
     */
    Name() = default;

    /** @name Construction methods
     * @{
     */

    /**
     * @brief Create a Name from a URI string
     *
     * Parses an NDN URI format string and constructs a Name.
     * The "ndn:" prefix is optional.
     *
     * @param uri URI string (e.g., "/sensor/temperature" or "ndn:/sensor/temperature")
     * @return Name and Error::Success on success, error code on failure
     *
     * @note Percent-encoding (%XX) is supported.
     */
    static Result<Name> fromUri(std::string_view uri);

    /**
     * @brief Decode a Name from TLV wire format
     *
     * @param buf Input buffer
     * @param len Buffer length
     * @param bytesRead Pointer to store the number of bytes read (may be nullptr)
     * @return Name and Error::Success on success
     */
    static Result<Name> fromWire(const uint8_t* buf, size_t len, size_t* bytesRead = nullptr);
    /** @} */

    /** @name Conversion methods
     * @{
     */

    /**
     * @brief Convert the Name to a URI string
     *
     * @param buf Output buffer
     * @param bufSize Buffer size
     * @return Number of characters written (excluding null terminator)
     */
    size_t toUri(char* buf, size_t bufSize) const;

    /**
     * @brief Encode the Name to TLV wire format
     *
     * @param buf Output buffer
     * @param bufSize Buffer size
     * @param encodedLen Stores the number of encoded bytes
     * @return Error::Success on success
     */
    Error encode(uint8_t* buf, size_t bufSize, size_t& encodedLen) const;
    /** @} */

    /** @name Component operations
     * @{
     */

    /**
     * @brief Get the number of components
     * @return Number of components in the Name
     */
    size_t componentCount() const { return numComponents_; }

    /**
     * @brief Get the component at a given index
     *
     * @param index Component index (starting from 0)
     * @return NameComponent structure
     * @note Behavior is undefined if the index is out of range
     */
    NameComponent component(size_t index) const;

    /**
     * @brief Append a string component
     *
     * @param comp Component string to append
     * @return Error::Success on success,
     *         Error::BufferTooSmall if buffer is insufficient,
     *         Error::TooManyComponents if component limit exceeded
     */
    Error appendComponent(std::string_view comp);

    /**
     * @brief Append a binary component
     *
     * @param value Pointer to component value
     * @param len Size of the component in bytes
     * @return Error::Success on success
     */
    Error appendComponent(const uint8_t* value, size_t len);
    /** @} */

    /** @name Comparison methods
     * @{
     */

    /**
     * @brief Compare with another Name
     *
     * Performs lexicographic comparison according to the NDN specification.
     *
     * @param other Name to compare with
     * @return Negative: this < other, 0: this == other, Positive: this > other
     */
    int compare(const Name& other) const;

    /**
     * @brief Check equality with another Name
     *
     * @param other Name to compare with
     * @return true if equal
     */
    bool equals(const Name& other) const;

    /**
     * @brief Check if this Name is a prefix of another Name
     *
     * @param other Name to compare with
     * @return true if this Name is a prefix of other
     *
     * @code
     * Name prefix, full;
     * prefix.appendComponent("sensor");
     * full.appendComponent("sensor");
     * full.appendComponent("temperature");
     * assert(prefix.isPrefixOf(full));  // true
     * @endcode
     */
    bool isPrefixOf(const Name& other) const;
    /** @} */

    /**
     * @brief Compute hash value of the Name
     *
     * Returns a 32-bit hash value used for lookups in PIT and CS.
     *
     * @return 32-bit hash value
     */
    uint32_t hash() const;

    /** @name State inspection
     * @{
     */

    /**
     * @brief Check if the Name is empty
     * @return true if there are no components
     */
    bool empty() const { return numComponents_ == 0; }

    /**
     * @brief Get pointer to the internal buffer
     * @return Pointer to the TLV-encoded Name Value portion
     */
    const uint8_t* wireValue() const { return buffer_.data(); }

    /**
     * @brief Get the length of the internal buffer
     * @return Length in bytes of the TLV-encoded Name Value portion
     */
    size_t wireLength() const { return length_; }
    /** @} */

private:
    std::array<uint8_t, NAME_MAX_LENGTH> buffer_{};  ///< Stores TLV-encoded components
    size_t length_ = 0;                              ///< Used buffer length

    /**
     * @brief Structure recording component offset and length
     */
    struct ComponentOffset {
        uint16_t offset;  ///< Offset within the buffer
        uint16_t length;  ///< Component length
    };
    std::array<ComponentOffset, NAME_MAX_COMPONENTS> components_{};  ///< Component position table
    uint8_t numComponents_ = 0;                                      ///< Number of components

    /**
     * @brief Internal implementation of component append
     * @param value Component value
     * @param len Length
     * @return Error code
     */
    Error appendComponentInternal(const uint8_t* value, size_t len);
};

/** @name Comparison operators
 * @{
 */

/**
 * @brief Equality operator
 * @param lhs Left-hand side Name
 * @param rhs Right-hand side Name
 * @return true if equal
 */
inline bool operator==(const Name& lhs, const Name& rhs) {
    return lhs.equals(rhs);
}

/**
 * @brief Inequality operator
 * @param lhs Left-hand side Name
 * @param rhs Right-hand side Name
 * @return true if not equal
 */
inline bool operator!=(const Name& lhs, const Name& rhs) {
    return !lhs.equals(rhs);
}

/**
 * @brief Less-than operator
 * @param lhs Left-hand side Name
 * @param rhs Right-hand side Name
 * @return true if lhs < rhs
 */
inline bool operator<(const Name& lhs, const Name& rhs) {
    return lhs.compare(rhs) < 0;
}
/** @} */

}  // namespace ndn
