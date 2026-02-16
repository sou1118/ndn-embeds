/**
 * @file data.hpp
 * @brief NDN Data packet
 *
 * Provides a class representing NDN Data packets.
 * A Data packet is returned as a response to an Interest, containing fields
 * such as Name, Content, and FreshnessPeriod.
 *
 * @see https://docs.named-data.net/NDN-packet-spec/current/data.html
 */

#pragma once

#include "ndn/common.hpp"
#include "ndn/name.hpp"
#include "ndn/signature.hpp"

namespace ndn {

/**
 * @brief NDN Data packet
 *
 * A Data packet contains the content returned by a producer in response to an Interest.
 * Only the Name field is required; Content and FreshnessPeriod are optional.
 *
 * @code
 * // Create and configure a Data packet
 * ndn::Data data;
 * data.setName("/sensor/temperature");
 * data.setContent("25.5 C");
 * data.setFreshnessPeriod(10000);  // Valid for 10 seconds
 *
 * // Encode
 * uint8_t buf[256];
 * size_t len = 0;
 * if (data.encode(buf, sizeof(buf), len) == ndn::Error::Success) {
 *     // Send buf over the network
 * }
 *
 * // Decode
 * auto result = ndn::Data::fromWire(buf, len);
 * if (result.ok()) {
 *     printf("Content: %.*s\n",
 *            (int)result.value.contentSize(),
 *            result.value.content());
 * }
 * @endcode
 */
class Data {
public:
    /**
     * @brief Default constructor
     *
     * Creates an empty Data packet. Name is empty, Content is empty,
     * and FreshnessPeriod is unset.
     */
    Data() = default;

    /**
     * @brief Create a Data packet with a specified Name
     * @param name The Data name
     */
    explicit Data(const Name& name);

    /** @name Decoding
     * @{
     */

    /**
     * @brief Decode a Data packet from TLV wire format
     *
     * @param buf Input buffer
     * @param len Buffer length
     * @return Data and Error::Success on success,
     *         Error::InvalidPacket if TLV Type is not 0x06,
     *         Error::InvalidPacket if Name is missing
     */
    static Result<Data> fromWire(const uint8_t* buf, size_t len);
    /** @} */

    /** @name Encoding
     * @{
     */

    /**
     * @brief Encode the Data packet to TLV wire format
     *
     * @param buf Output buffer
     * @param bufSize Buffer size
     * @param encodedLen Stores the number of encoded bytes
     * @return Error::Success on success, Error::BufferTooSmall if buffer is insufficient
     */
    Error encode(uint8_t* buf, size_t bufSize, size_t& encodedLen) const;
    /** @} */

    /** @name Name field
     * @{
     */

    /**
     * @brief Get the Name (const reference)
     * @return Const reference to the Name
     */
    const Name& name() const { return name_; }

    /**
     * @brief Get the Name (reference)
     * @return Reference to the Name
     */
    Name& name() { return name_; }

    /**
     * @brief Set the Name (supports method chaining)
     * @param name Name to set
     * @return Reference to this Data
     */
    Data& setName(const Name& name);

    /**
     * @brief Set the Name from a URI string
     * @param uri URI string (e.g., "/sensor/temperature")
     * @return Error::Success on success, error code on parse failure
     */
    Error setName(std::string_view uri);
    /** @} */

    /** @name Content field
     * @{
     */

    /**
     * @brief Get a pointer to the content data
     * @return Pointer to the content buffer
     */
    const uint8_t* content() const { return content_.data(); }

    /**
     * @brief Get the content size
     * @return Content size in bytes
     */
    size_t contentSize() const { return contentSize_; }

    /**
     * @brief Check if content is set
     * @return true if content is present
     */
    bool hasContent() const { return contentSize_ > 0; }

    /**
     * @brief Set binary data as content
     *
     * @param data Pointer to the content data
     * @param size Data size (bytes)
     * @return Error::Success on success,
     *         Error::BufferTooSmall if size exceeds DATA_MAX_CONTENT_SIZE
     */
    Error setContent(const uint8_t* data, size_t size);

    /**
     * @brief Set a string as content
     *
     * @param str Content string
     * @return Error::Success on success,
     *         Error::BufferTooSmall if size exceeds DATA_MAX_CONTENT_SIZE
     */
    Error setContent(std::string_view str);
    /** @} */

    /** @name ContentType field
     * @{
     */

    /**
     * @brief Get the content type
     * @return Content type
     */
    ContentType contentType() const { return contentType_; }

    /**
     * @brief Set the content type
     * @param type Content type
     * @return Reference to this Data
     */
    Data& setContentType(ContentType type);

    /**
     * @brief Check if this is a Link Object
     * @return true if ContentType::Link
     */
    bool isLink() const { return contentType_ == ContentType::Link; }
    /** @} */

    /** @name FreshnessPeriod field
     * @{
     */

    /**
     * @brief Get the FreshnessPeriod
     *
     * FreshnessPeriod indicates the freshness duration of the Data (milliseconds).
     * Within this period, cached responses from the Content Store are possible.
     *
     * @return FreshnessPeriod (milliseconds) if set, nullopt if unset
     */
    std::optional<uint32_t> freshnessPeriod() const { return freshnessPeriod_; }

    /**
     * @brief Set the FreshnessPeriod
     * @param periodMs Freshness period (milliseconds)
     * @return Reference to this Data
     */
    Data& setFreshnessPeriod(uint32_t periodMs);
    /** @} */

    /** @name FinalBlockId field
     * @{
     */

    /**
     * @brief Get the FinalBlockId
     *
     * FinalBlockId indicates the last segment number in segmented transfer.
     * The segment number is typically used as the last component of the Name.
     *
     * @return FinalBlockId value if set, nullopt if unset
     */
    std::optional<uint64_t> finalBlockId() const { return finalBlockId_; }

    /**
     * @brief Check if FinalBlockId is set
     * @return true if FinalBlockId is present
     */
    bool hasFinalBlockId() const { return finalBlockId_.has_value(); }

    /**
     * @brief Set the FinalBlockId
     *
     * Sets the last segment number in segmented transfer.
     *
     * @param segmentNum Last segment number
     * @return Reference to this Data
     */
    Data& setFinalBlockId(uint64_t segmentNum);

    /**
     * @brief Clear the FinalBlockId
     * @return Reference to this Data
     */
    Data& clearFinalBlockId();
    /** @} */

    /** @name Signature fields
     * @{
     */

    /**
     * @brief Get the signature type
     * @return Signature type
     */
    SignatureType signatureType() const { return signatureType_; }

    /**
     * @brief Set the signature type
     * @param type Signature type
     * @return Reference to this Data
     */
    Data& setSignatureType(SignatureType type);

    /**
     * @brief Get the KeyLocator
     *
     * Returns the reference information (Name) of the key used for signing.
     * Required for RSA/ECDSA/Ed25519 signatures, prohibited for DigestSha256.
     *
     * @return KeyLocator Name if set, nullptr if unset
     */
    const Name* keyLocator() const { return hasKeyLocator_ ? &keyLocator_ : nullptr; }

    /**
     * @brief Check if KeyLocator is set
     * @return true if KeyLocator is present
     */
    bool hasKeyLocator() const { return hasKeyLocator_; }

    /**
     * @brief Set the KeyLocator
     * @param name Name identifying the key
     * @return Reference to this Data
     */
    Data& setKeyLocator(const Name& name);

    /**
     * @brief Clear the KeyLocator
     * @return Reference to this Data
     */
    Data& clearKeyLocator();

    /**
     * @brief Get a pointer to the signature value
     * @return Pointer to the signature value buffer
     */
    const uint8_t* signatureValue() const { return signatureValue_.data(); }

    /**
     * @brief Get the size of the signature value
     * @return Size of the signature value in bytes
     */
    size_t signatureValueSize() const { return signatureSize_; }

    /**
     * @brief Check if a signature is set
     * @return true if a signature is present
     */
    bool hasSignature() const { return signatureSize_ > 0; }

    /**
     * @brief Sign with DigestSha256
     *
     * Computes a SHA-256 digest from Name, MetaInfo, Content, and SignatureInfo,
     * and stores it in SignatureValue. signatureType is set to DigestSha256.
     *
     * @return Error::Success on success
     */
    Error signWithDigestSha256();

    /**
     * @brief Sign with HMAC-SHA256
     *
     * Computes HMAC-SHA256 using the specified key and stores it in SignatureValue.
     * signatureType is set to SignatureHmacWithSha256.
     *
     * @param key Pointer to the key data
     * @param keyLen Key length (bytes)
     * @return Error::Success on success
     */
    Error signWithHmac(const uint8_t* key, size_t keyLen);

    /**
     * @brief Verify a DigestSha256 signature
     *
     * @return true if the signature is valid
     */
    bool verifyDigestSha256() const;

    /**
     * @brief Verify an HMAC-SHA256 signature
     *
     * @param key Pointer to the key data
     * @param keyLen Key length (bytes)
     * @return true if the signature is valid
     */
    bool verifyHmac(const uint8_t* key, size_t keyLen) const;

    /**
     * @brief Sign with ECDSA P-256
     *
     * Computes an ECDSA signature using the specified private key and stores
     * it in SignatureValue. signatureType is set to SignatureSha256WithEcdsa.
     * It is recommended to set the KeyLocator beforehand.
     *
     * @param privKey Private key (32 bytes)
     * @return Error::Success on success
     */
    Error signWithEcdsa(const uint8_t* privKey);

    /**
     * @brief Verify an ECDSA P-256 signature
     *
     * @param pubKey Public key (65 bytes, uncompressed form)
     * @return true if the signature is valid
     */
    bool verifyEcdsa(const uint8_t* pubKey) const;
    /** @} */

private:
    /**
     * @brief Encode the SignedData portion (for signature computation)
     *
     * Encodes Name + MetaInfo + Content + SignatureInfo into the buffer.
     *
     * @param buf Output buffer
     * @param bufSize Buffer size
     * @param encodedLen Stores the number of encoded bytes
     * @return Error::Success on success
     */
    Error encodeSignedPortion(uint8_t* buf, size_t bufSize, size_t& encodedLen) const;

    Name name_;                                                  ///< Data name
    std::array<uint8_t, DATA_MAX_CONTENT_SIZE> content_{};       ///< Content buffer
    size_t contentSize_ = 0;                                     ///< Content size
    ContentType contentType_ = ContentType::Blob;                ///< Content type
    std::optional<uint32_t> freshnessPeriod_;                    ///< FreshnessPeriod (ms)
    std::optional<uint64_t> finalBlockId_;                       ///< FinalBlockId (segment number)
    SignatureType signatureType_ = SignatureType::DigestSha256;  ///< Signature type
    Name keyLocator_;                                            ///< KeyLocator (Name)
    bool hasKeyLocator_ = false;                                 ///< KeyLocator set flag
    std::array<uint8_t, SIGNATURE_MAX_SIZE> signatureValue_{};   ///< Signature value buffer
    size_t signatureSize_ = 0;                                   ///< Signature value size
};

}  // namespace ndn
