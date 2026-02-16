/**
 * @file signature.hpp
 * @brief NDN signature types and constants
 *
 * Defines types and constants related to NDN packet signatures.
 *
 * @see https://docs.named-data.net/NDN-packet-spec/current/signature.html
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace ndn {

/**
 * @brief Signature type
 *
 * Represents signature algorithms defined in the NDN specification.
 */
enum class SignatureType : uint8_t {
    DigestSha256 = 0,              ///< SHA-256 digest (integrity only)
    SignatureSha256WithRsa = 1,    ///< RSA signature (PKCS#1 v1.5)
    SignatureSha256WithEcdsa = 3,  ///< ECDSA signature
    SignatureHmacWithSha256 = 4,   ///< HMAC-SHA256 (shared key)
    SignatureEd25519 = 5,          ///< Ed25519 signature
};

/** @name Signature size constants
 * @{
 */
constexpr size_t SHA256_DIGEST_SIZE = 32;       ///< SHA-256 digest size (bytes)
constexpr size_t HMAC_SHA256_SIZE = 32;         ///< HMAC-SHA256 size (bytes)
constexpr size_t ECDSA_P256_SIG_MAX_SIZE = 72;  ///< ECDSA P-256 signature max size (DER format)
constexpr size_t ED25519_SIG_SIZE = 64;         ///< Ed25519 signature size (bytes)
constexpr size_t RSA_2048_SIG_SIZE = 256;       ///< RSA-2048 signature size (bytes)
constexpr size_t SIGNATURE_MAX_SIZE = 72;  ///< Maximum signature size (for ECDSA P-256, embedded)
/** @} */

/** @name Public key size constants
 * @{
 */
constexpr size_t ECDSA_P256_PUBKEY_SIZE = 65;   ///< ECDSA P-256 public key size (uncompressed form)
constexpr size_t ECDSA_P256_PRIVKEY_SIZE = 32;  ///< ECDSA P-256 private key size
constexpr size_t ED25519_PUBKEY_SIZE = 32;      ///< Ed25519 public key size
constexpr size_t ED25519_PRIVKEY_SIZE = 32;     ///< Ed25519 private key size
/** @} */

/**
 * @brief Convert signature type to string
 * @param type Signature type
 * @return String representation of the signature type
 */
constexpr const char* signatureTypeToString(SignatureType type) {
    switch (type) {
        case SignatureType::DigestSha256:
            return "DigestSha256";
        case SignatureType::SignatureSha256WithRsa:
            return "SignatureSha256WithRsa";
        case SignatureType::SignatureSha256WithEcdsa:
            return "SignatureSha256WithEcdsa";
        case SignatureType::SignatureHmacWithSha256:
            return "SignatureHmacWithSha256";
        case SignatureType::SignatureEd25519:
            return "SignatureEd25519";
        default:
            return "Unknown";
    }
}

}  // namespace ndn
