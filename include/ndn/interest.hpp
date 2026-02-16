/**
 * @file interest.hpp
 * @brief NDN Interest packet
 *
 * Provides a class representing NDN Interest packets.
 * An Interest is a packet used to request data, containing fields such as
 * Name, Nonce, InterestLifetime, and HopLimit.
 *
 * @see https://docs.named-data.net/NDN-packet-spec/current/interest.html
 */

#pragma once

#include "ndn/common.hpp"
#include "ndn/name.hpp"
#include "ndn/signature.hpp"

namespace ndn {

class TlvEncoder;
class TlvDecoder;

/**
 * @brief NDN Interest packet
 *
 * An Interest packet is sent by a consumer to request data.
 * Only the Name field is required; all other fields are optional.
 *
 * @code
 * // Create and configure an Interest
 * ndn::Interest interest;
 * interest.setName("/sensor/temperature");
 * interest.setLifetime(5000);
 * interest.generateNonce();
 *
 * // Encode
 * uint8_t buf[128];
 * size_t len = 0;
 * if (interest.encode(buf, sizeof(buf), len) == ndn::Error::Success) {
 *     // Send buf over the network
 * }
 *
 * // Decode
 * auto result = ndn::Interest::fromWire(buf, len);
 * if (result.ok()) {
 *     printf("Interest for: %s\n", result.value.name().toUri(...));
 * }
 * @endcode
 */
class Interest {
public:
    /**
     * @brief Default constructor
     *
     * Creates an empty Interest. Name is empty, Nonce is unset,
     * and lifetime is set to the default value (4000ms).
     */
    Interest() = default;

    /**
     * @brief Create an Interest with a specified Name
     * @param name The Interest name
     */
    explicit Interest(const Name& name);

    /** @name Decoding
     * @{
     */

    /**
     * @brief Decode an Interest from TLV wire format
     *
     * @param buf Input buffer
     * @param len Buffer length
     * @return Interest and Error::Success on success,
     *         Error::InvalidPacket if TLV Type is not 0x05,
     *         Error::InvalidPacket if Name is missing
     */
    static Result<Interest> fromWire(const uint8_t* buf, size_t len);
    /** @} */

    /** @name Encoding
     * @{
     */

    /**
     * @brief Encode the Interest to TLV wire format
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
     * @return Reference to this Interest
     */
    Interest& setName(const Name& name);

    /**
     * @brief Set the Name from a URI string
     * @param uri URI string (e.g., "/sensor/temperature")
     * @return Error::Success on success, error code on parse failure
     */
    Error setName(std::string_view uri);
    /** @} */

    /** @name Nonce field
     * @{
     */

    /**
     * @brief Get the Nonce
     *
     * The Nonce is a 32-bit random value used for loop detection.
     *
     * @return Nonce value if set, nullopt if unset
     */
    std::optional<uint32_t> nonce() const { return nonce_; }

    /**
     * @brief Set the Nonce
     * @param nonce Nonce value to set
     * @return Reference to this Interest
     */
    Interest& setNonce(uint32_t nonce);

    /**
     * @brief Generate and set a random Nonce
     * @return Reference to this Interest
     */
    Interest& generateNonce();
    /** @} */

    /** @name InterestLifetime field
     * @{
     */

    /**
     * @brief Get the InterestLifetime
     *
     * Returns the Interest's lifetime in milliseconds.
     * Default value is 4000ms (INTEREST_DEFAULT_LIFETIME_MS).
     *
     * @return InterestLifetime (milliseconds)
     */
    uint32_t lifetime() const { return lifetime_; }

    /**
     * @brief Set the InterestLifetime
     * @param lifetimeMs Lifetime (milliseconds)
     * @return Reference to this Interest
     */
    Interest& setLifetime(uint32_t lifetimeMs);
    /** @} */

    /** @name HopLimit field
     * @{
     */

    /**
     * @brief Get the HopLimit
     *
     * HopLimit is the maximum number of hops an Interest can traverse.
     * It decreases by 1 at each hop and is not forwarded when it reaches 0.
     *
     * @return HopLimit value (0-255) if set, nullopt if unset
     */
    std::optional<uint8_t> hopLimit() const { return hopLimit_; }

    /**
     * @brief Set the HopLimit
     * @param limit HopLimit value (0-255)
     * @return Reference to this Interest
     */
    Interest& setHopLimit(uint8_t limit);

    /**
     * @brief Decrement the HopLimit by 1
     *
     * If HopLimit is set, decrements it by 1.
     * If it is already 0, it remains 0.
     *
     * @return Reference to this Interest
     */
    Interest& decrementHopLimit();
    /** @} */

    /** @name CanBePrefix field
     * @{
     */

    /**
     * @brief Get the CanBePrefix flag
     *
     * When true, this Interest also accepts Data whose Name matches as a prefix.
     *
     * @return CanBePrefix flag (default is false)
     */
    bool canBePrefix() const { return canBePrefix_; }

    /**
     * @brief Set the CanBePrefix flag
     * @param canBePrefix true to allow prefix matching
     * @return Reference to this Interest
     */
    Interest& setCanBePrefix(bool canBePrefix);
    /** @} */

    /** @name MustBeFresh field
     * @{
     */

    /**
     * @brief Get the MustBeFresh flag
     *
     * When true, Data returned from the Content Store must be fresh
     * (within its FreshnessPeriod).
     *
     * @return MustBeFresh flag (default is false)
     */
    bool mustBeFresh() const { return mustBeFresh_; }

    /**
     * @brief Set the MustBeFresh flag
     * @param mustBeFresh true to accept only fresh Data
     * @return Reference to this Interest
     */
    Interest& setMustBeFresh(bool mustBeFresh);
    /** @} */

    /** @name ForwardingHint field
     * @{
     */

    /**
     * @brief Add a ForwardingHint
     *
     * ForwardingHint is a list of Names indicating routes to the producer.
     * Delegations obtained from a Link Object can be set here.
     *
     * @param name Name to add
     * @return Error::Success on success, Error::Full when at capacity
     */
    Error addForwardingHint(const Name& name);

    /**
     * @brief Add a ForwardingHint from a URI string
     * @param uri URI string
     * @return Error::Success on success
     */
    Error addForwardingHint(std::string_view uri);

    /**
     * @brief Get the number of ForwardingHints
     * @return Number of ForwardingHints
     */
    size_t forwardingHintCount() const { return fwHintCount_; }

    /**
     * @brief Get a ForwardingHint by index
     * @param index Index (starting from 0)
     * @return Pointer to the Name at the given index, nullptr if out of range
     */
    const Name* forwardingHint(size_t index) const;

    /**
     * @brief Clear all ForwardingHints
     */
    void clearForwardingHints();

    /**
     * @brief Check if ForwardingHints are set
     * @return true if ForwardingHints are present
     */
    bool hasForwardingHint() const { return fwHintCount_ > 0; }
    /** @} */

    /** @name ApplicationParameters field
     * @{
     */

    /**
     * @brief Get the ApplicationParameters
     * @return Pointer to the parameter data, nullptr if unset
     */
    const uint8_t* applicationParameters() const {
        return appParamsLen_ > 0 ? appParams_ : nullptr;
    }

    /**
     * @brief Get the size of ApplicationParameters
     * @return Size of the parameters in bytes
     */
    size_t applicationParametersSize() const { return appParamsLen_; }

    /**
     * @brief Set ApplicationParameters
     *
     * Data is copied to an internal buffer.
     *
     * @param params Pointer to the parameter data
     * @param len Size of the parameters in bytes
     * @return Reference to this Interest
     */
    Interest& setApplicationParameters(const uint8_t* params, size_t len);
    /** @} */

    /** @name Signature fields
     * @{
     */

    /**
     * @brief Check if the Interest is signed
     * @return true if a signature is present
     */
    bool isSigned() const { return signatureSize_ > 0; }

    /**
     * @brief Get the signature type
     * @return Signature type
     */
    SignatureType signatureType() const { return signatureType_; }

    /**
     * @brief Get the signature nonce
     *
     * A random value for replay attack prevention.
     *
     * @return Pointer to the signature nonce (8 bytes), nullptr if unset
     */
    const uint8_t* signatureNonce() const { return hasSignatureNonce_ ? signatureNonce_ : nullptr; }

    /**
     * @brief Get the signature time
     *
     * @return Signature time (milliseconds Unix epoch) if set, nullopt if unset
     */
    std::optional<uint64_t> signatureTime() const { return signatureTime_; }

    /**
     * @brief Get the signature sequence number
     *
     * A sequence number for replay attack prevention.
     * Can be used in combination with SignatureNonce and SignatureTime.
     *
     * @return Sequence number if set, nullopt if unset
     */
    std::optional<uint64_t> signatureSeqNum() const { return signatureSeqNum_; }

    /**
     * @brief Set the signature sequence number
     * @param seqNum Sequence number
     * @return Reference to this Interest
     */
    Interest& setSignatureSeqNum(uint64_t seqNum);

    /**
     * @brief Get the KeyLocator
     *
     * Returns the reference information (Name) of the key used for signing.
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
     * @return Reference to this Interest
     */
    Interest& setKeyLocator(const Name& name);

    /**
     * @brief Clear the KeyLocator
     * @return Reference to this Interest
     */
    Interest& clearKeyLocator();

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
     * @brief Sign with DigestSha256
     *
     * Computes a SHA-256 digest from the TLV starting at ApplicationParameters,
     * and stores it in InterestSignatureValue.
     *
     * @return Error::Success on success
     */
    Error signWithDigestSha256();

    /**
     * @brief Sign with HMAC-SHA256
     *
     * Computes HMAC-SHA256 using the specified key and stores it in
     * InterestSignatureValue.
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
     * it in InterestSignatureValue.
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
     * @brief Encode the signed portion (for signature computation)
     *
     * Encodes Name + ApplicationParameters + InterestSignatureInfo into the buffer.
     *
     * @param buf Output buffer
     * @param bufSize Buffer size
     * @param encodedLen Stores the number of encoded bytes
     * @return Error::Success on success
     */
    Error encodeSignedPortion(uint8_t* buf, size_t bufSize, size_t& encodedLen) const;

    /**
     * @brief Generate a signature nonce
     */
    void generateSignatureNonce();

    /**
     * @brief Encode InterestSignatureInfo TLV into the given encoder
     * @param encoder The TLV encoder to write to
     * @return Error::Success on success
     */
    Error encodeInterestSignatureInfo(TlvEncoder& encoder) const;

    /**
     * @brief Parse InterestSignatureInfo fields from a TLV decoder
     * @param decoder The TLV decoder to read from
     * @param elemLen Length of the InterestSignatureInfo element
     * @param interest The Interest object to populate
     * @return Error::Success on success
     */
    static Error parseSignatureInfo(TlvDecoder& decoder, size_t elemLen, Interest& interest);

    /** @brief Maximum size of ApplicationParameters */
    static constexpr size_t APP_PARAMS_MAX_SIZE = 200;

    /** @brief Signature nonce size (bytes) */
    static constexpr size_t SIGNATURE_NONCE_SIZE = 8;

    /** @brief Maximum number of ForwardingHints */
    static constexpr size_t FW_HINT_MAX_COUNT = LINK_MAX_DELEGATIONS;

    Name name_;                                         ///< Interest name
    std::optional<uint32_t> nonce_;                     ///< Nonce (for loop detection)
    uint32_t lifetime_ = INTEREST_DEFAULT_LIFETIME_MS;  ///< InterestLifetime (ms)
    std::optional<uint8_t> hopLimit_;                   ///< HopLimit
    bool canBePrefix_ = false;                          ///< CanBePrefix flag
    bool mustBeFresh_ = false;                          ///< MustBeFresh flag
    std::array<Name, FW_HINT_MAX_COUNT> fwHints_{};     ///< ForwardingHint list
    size_t fwHintCount_ = 0;                            ///< ForwardingHint count
    uint8_t appParams_[APP_PARAMS_MAX_SIZE] = {};       ///< ApplicationParameters
    size_t appParamsLen_ = 0;                           ///< ApplicationParameters length

    // Signature-related fields
    SignatureType signatureType_ = SignatureType::DigestSha256;  ///< Signature type
    uint8_t signatureNonce_[SIGNATURE_NONCE_SIZE] = {};          ///< Signature nonce
    bool hasSignatureNonce_ = false;                             ///< Signature nonce set flag
    std::optional<uint64_t> signatureTime_;                      ///< Signature time
    std::optional<uint64_t> signatureSeqNum_;                    ///< Signature sequence number
    Name keyLocator_;                                            ///< KeyLocator (Name)
    bool hasKeyLocator_ = false;                                 ///< KeyLocator set flag
    std::array<uint8_t, SIGNATURE_MAX_SIZE> signatureValue_{};   ///< Signature value buffer
    size_t signatureSize_ = 0;                                   ///< Signature value size
};

}  // namespace ndn
