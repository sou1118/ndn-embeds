/**
 * @file certificate.hpp
 * @brief NDN Certificate
 *
 * Provides a class representing NDN certificates.
 * A certificate is a special Data packet with ContentType=KEY,
 * containing a public key and its validity period.
 *
 * @see https://docs.named-data.net/NDN-packet-spec/current/certificate.html
 */

#pragma once

#include "ndn/common.hpp"
#include "ndn/data.hpp"
#include "ndn/name.hpp"

namespace ndn {

/** @brief Length of ValidityPeriod ISO 8601 format string (YYYYMMDDThhmmss) */
constexpr size_t VALIDITY_TIMESTAMP_SIZE = 15;

/** @brief Maximum public key size (DER-encoded SubjectPublicKeyInfo) */
constexpr size_t CERTIFICATE_MAX_KEY_SIZE = 256;

/**
 * @brief Validity period
 *
 * Represents a certificate's validity period. Consists of two timestamps:
 * NotBefore and NotAfter. Timestamps are expressed in ISO 8601-1:2019
 * compact format (YYYYMMDDThhmmss).
 *
 * @code
 * ndn::ValidityPeriod vp;
 * vp.setNotBefore(2024, 1, 1, 0, 0, 0);
 * vp.setNotAfter(2025, 12, 31, 23, 59, 59);
 *
 * if (vp.isValid()) {
 *     printf("Certificate is valid now\n");
 * }
 * @endcode
 */
class ValidityPeriod {
public:
    /**
     * @brief Default constructor
     *
     * Initialized with NotBefore=approximate current time, NotAfter=approximate 1 year later
     */
    ValidityPeriod() = default;

    /**
     * @brief Create a ValidityPeriod from ISO 8601 format strings
     *
     * @param notBefore Start time (YYYYMMDDThhmmss format)
     * @param notAfter End time (YYYYMMDDThhmmss format)
     * @return ValidityPeriod on success, error on failure
     */
    static Result<ValidityPeriod> fromStrings(std::string_view notBefore,
                                              std::string_view notAfter);

    /**
     * @brief Decode a ValidityPeriod from TLV wire format
     *
     * @param buf Input buffer
     * @param len Buffer length
     * @param bytesRead Stores the number of bytes read (ignored if nullptr)
     * @return ValidityPeriod on success, error on failure
     */
    static Result<ValidityPeriod> fromWire(const uint8_t* buf, size_t len,
                                           size_t* bytesRead = nullptr);

    /**
     * @brief Encode the ValidityPeriod to TLV wire format
     *
     * @param buf Output buffer
     * @param bufSize Buffer size
     * @param encodedLen Stores the number of encoded bytes
     * @return Error::Success on success
     */
    Error encode(uint8_t* buf, size_t bufSize, size_t& encodedLen) const;

    /** @name NotBefore
     * @{
     */

    /**
     * @brief Set the NotBefore time from date/time components
     *
     * @param year Year (e.g., 2024)
     * @param month Month (1-12)
     * @param day Day (1-31)
     * @param hour Hour (0-23)
     * @param minute Minute (0-59)
     * @param second Second (0-59)
     * @return Error::Success on success
     */
    Error setNotBefore(uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute,
                       uint8_t second);

    /**
     * @brief Set the NotBefore time from an ISO 8601 string
     * @param timestamp String in YYYYMMDDThhmmss format
     * @return Error::Success on success
     */
    Error setNotBefore(std::string_view timestamp);

    /**
     * @brief Get the NotBefore time as an ISO 8601 string
     * @return 15-character timestamp string (not null-terminated)
     */
    const char* notBefore() const { return notBefore_.data(); }
    /** @} */

    /** @name NotAfter
     * @{
     */

    /**
     * @brief Set the NotAfter time from date/time components
     */
    Error setNotAfter(uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute,
                      uint8_t second);

    /**
     * @brief Set the NotAfter time from an ISO 8601 string
     * @param timestamp String in YYYYMMDDThhmmss format
     * @return Error::Success on success
     */
    Error setNotAfter(std::string_view timestamp);

    /**
     * @brief Get the NotAfter time as an ISO 8601 string
     * @return 15-character timestamp string (not null-terminated)
     */
    const char* notAfter() const { return notAfter_.data(); }
    /** @} */

    /**
     * @brief Check if the current time is within the validity period
     *
     * @param currentTimestamp Current time (YYYYMMDDThhmmss format)
     * @return true if within the validity period
     */
    bool isValidAt(std::string_view currentTimestamp) const;

    /**
     * @brief Check equality of two validity periods
     */
    bool equals(const ValidityPeriod& other) const;

private:
    std::array<char, VALIDITY_TIMESTAMP_SIZE> notBefore_{};
    std::array<char, VALIDITY_TIMESTAMP_SIZE> notAfter_{};
};

/**
 * @brief NDN Certificate
 *
 * A class representing an NDN certificate. A certificate is a special Data packet
 * with ContentType=KEY, Content=public key (DER format), and a ValidityPeriod
 * in the SignatureInfo.
 *
 * Certificate name format: /<IdentityName>/KEY/<KeyId>/<IssuerId>/<Version>
 *
 * @code
 * ndn::Certificate cert;
 * cert.setIdentityName("/example/user");
 * cert.setKeyId(keyIdBytes, 8);
 * cert.setIssuerId("self");
 * cert.setVersion(1);
 * cert.setPublicKey(derEncodedKey, keyLen);
 * cert.validity().setNotBefore(2024, 1, 1, 0, 0, 0);
 * cert.validity().setNotAfter(2025, 12, 31, 23, 59, 59);
 *
 * // Self-sign
 * cert.signWithDigestSha256();
 *
 * // Encode as Data packet
 * uint8_t buf[512];
 * size_t len;
 * cert.encode(buf, sizeof(buf), len);
 * @endcode
 */
class Certificate {
public:
    /**
     * @brief Default constructor
     */
    Certificate() = default;

    /**
     * @brief Create a Certificate from a Data packet
     *
     * @param data Data packet
     * @return Certificate on success, error if ContentType != KEY
     */
    static Result<Certificate> fromData(const Data& data);

    /**
     * @brief Decode a Certificate from TLV wire format
     *
     * @param buf Input buffer
     * @param len Buffer length
     * @return Certificate on success, error on failure
     */
    static Result<Certificate> fromWire(const uint8_t* buf, size_t len);

    /**
     * @brief Convert the Certificate to a Data packet
     *
     * @param data Output Data packet
     * @return Error::Success on success
     */
    Error toData(Data& data) const;

    /**
     * @brief Encode the Certificate to TLV wire format
     *
     * @param buf Output buffer
     * @param bufSize Buffer size
     * @param encodedLen Stores the number of encoded bytes
     * @return Error::Success on success
     */
    Error encode(uint8_t* buf, size_t bufSize, size_t& encodedLen) const;

    /** @name Identity Name
     * @{
     */

    /**
     * @brief Get the identity name
     * @return Identity name
     */
    const Name& identityName() const { return identityName_; }

    /**
     * @brief Set the identity name
     * @param name Identity name
     * @return Reference to this Certificate
     */
    Certificate& setIdentityName(const Name& name);

    /**
     * @brief Set the identity name from a URI string
     * @param uri URI string
     * @return Error::Success on success
     */
    Error setIdentityName(std::string_view uri);
    /** @} */

    /** @name Key ID
     * @{
     */

    /**
     * @brief Get the Key ID
     * @return Pointer to Key ID bytes
     */
    const uint8_t* keyId() const { return keyId_.data(); }

    /**
     * @brief Get the Key ID size
     * @return Key ID size in bytes
     */
    size_t keyIdSize() const { return keyIdSize_; }

    /**
     * @brief Set the Key ID
     * @param id Key ID bytes
     * @param len Size in bytes
     * @return Error::Success on success
     */
    Error setKeyId(const uint8_t* id, size_t len);
    /** @} */

    /** @name Issuer ID
     * @{
     */

    /**
     * @brief Get the Issuer ID
     * @return Pointer to Issuer ID bytes
     */
    const uint8_t* issuerId() const { return issuerId_.data(); }

    /**
     * @brief Get the Issuer ID size
     * @return Issuer ID size in bytes
     */
    size_t issuerIdSize() const { return issuerIdSize_; }

    /**
     * @brief Set the Issuer ID (bytes)
     * @param id Issuer ID bytes
     * @param len Size in bytes
     * @return Error::Success on success
     */
    Error setIssuerId(const uint8_t* id, size_t len);

    /**
     * @brief Set the Issuer ID (string)
     * @param id Issuer ID string
     * @return Error::Success on success
     */
    Error setIssuerId(std::string_view id);
    /** @} */

    /** @name Version
     * @{
     */

    /**
     * @brief Get the version
     * @return Version number
     */
    uint64_t version() const { return version_; }

    /**
     * @brief Set the version
     * @param version Version number
     * @return Reference to this Certificate
     */
    Certificate& setVersion(uint64_t version);
    /** @} */

    /** @name Public Key
     * @{
     */

    /**
     * @brief Get the public key
     * @return Pointer to the DER-encoded public key
     */
    const uint8_t* publicKey() const { return publicKey_.data(); }

    /**
     * @brief Get the public key size
     * @return Public key size in bytes
     */
    size_t publicKeySize() const { return publicKeySize_; }

    /**
     * @brief Set the public key
     * @param key DER-encoded public key
     * @param len Size in bytes
     * @return Error::Success on success
     */
    Error setPublicKey(const uint8_t* key, size_t len);
    /** @} */

    /** @name Validity Period
     * @{
     */

    /**
     * @brief Get the validity period (const)
     * @return Reference to the validity period
     */
    const ValidityPeriod& validity() const { return validity_; }

    /**
     * @brief Get the validity period
     * @return Reference to the validity period
     */
    ValidityPeriod& validity() { return validity_; }

    /**
     * @brief Set the validity period
     * @param validity Validity period
     * @return Reference to this Certificate
     */
    Certificate& setValidity(const ValidityPeriod& validity);
    /** @} */

    /** @name Signature
     * @{
     */

    /**
     * @brief Get the signature type
     */
    SignatureType signatureType() const { return signatureType_; }

    /**
     * @brief Set the signature type
     */
    Certificate& setSignatureType(SignatureType type);

    /**
     * @brief Sign with DigestSha256
     * @return Error::Success on success
     */
    Error signWithDigestSha256();

    /**
     * @brief Sign with HMAC-SHA256
     * @param key Key data
     * @param keyLen Key length
     * @return Error::Success on success
     */
    Error signWithHmac(const uint8_t* key, size_t keyLen);

    /**
     * @brief Verify a DigestSha256 signature
     * @return true if the signature is valid
     */
    bool verifyDigestSha256() const;

    /**
     * @brief Verify an HMAC-SHA256 signature
     * @param key Key data
     * @param keyLen Key length
     * @return true if the signature is valid
     */
    bool verifyHmac(const uint8_t* key, size_t keyLen) const;
    /** @} */

    /**
     * @brief Build the full certificate name and store it in a Name
     *
     * /<IdentityName>/KEY/<KeyId>/<IssuerId>/<Version>
     *
     * @param name Output Name
     * @return Error::Success on success
     */
    Error buildName(Name& name) const;

    /**
     * @brief Check if the certificate is valid at a given time
     * @param timestamp ISO 8601 format time (YYYYMMDDThhmmss)
     * @return true if valid
     */
    bool isValidAt(std::string_view timestamp) const;

private:
    /**
     * @brief Encode the signed portion (Name + MetaInfo + Content + SignatureInfo)
     * @param buf Output buffer
     * @param bufSize Buffer size
     * @param encodedLen Stores the number of encoded bytes
     * @return Error::Success on success
     */
    Error encodeSignedPortion(uint8_t* buf, size_t bufSize, size_t& encodedLen) const;

    Name identityName_;                                          ///< Identity name
    std::array<uint8_t, 32> keyId_{};                            ///< Key ID
    size_t keyIdSize_ = 0;                                       ///< Key ID size
    std::array<uint8_t, 32> issuerId_{};                         ///< Issuer ID
    size_t issuerIdSize_ = 0;                                    ///< Issuer ID size
    uint64_t version_ = 0;                                       ///< Version
    std::array<uint8_t, CERTIFICATE_MAX_KEY_SIZE> publicKey_{};  ///< Public key
    size_t publicKeySize_ = 0;                                   ///< Public key size
    ValidityPeriod validity_;                                    ///< Validity period
    SignatureType signatureType_ = SignatureType::DigestSha256;  ///< Signature type
    std::array<uint8_t, SIGNATURE_MAX_SIZE> signatureValue_{};   ///< Signature value
    size_t signatureSize_ = 0;                                   ///< Signature size
};

}  // namespace ndn
