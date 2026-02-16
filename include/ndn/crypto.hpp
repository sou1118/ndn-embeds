/**
 * @file crypto.hpp
 * @brief NDN cryptographic utilities
 *
 * Provides utility functions for SHA-256 hash and HMAC-SHA256 computation.
 * Uses the mbedtls library from ESP-IDF.
 */

#pragma once

#include "ndn/common.hpp"

namespace ndn::crypto {

/**
 * @brief Compute SHA-256 hash
 *
 * @param data Pointer to input data
 * @param len Input data length (bytes)
 * @param out Output buffer (must be at least 32 bytes)
 * @return Error::Success on success
 */
Error sha256(const uint8_t* data, size_t len, uint8_t* out);

/**
 * @brief Compute HMAC-SHA256
 *
 * @param key Pointer to key data
 * @param keyLen Key length (bytes)
 * @param data Pointer to input data
 * @param dataLen Input data length (bytes)
 * @param out Output buffer (must be at least 32 bytes)
 * @return Error::Success on success
 */
Error hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen,
                 uint8_t* out);

/**
 * @brief Compare two buffers in constant time
 *
 * Always compares all bytes to prevent timing attacks.
 *
 * @param lhs First buffer
 * @param rhs Second buffer
 * @param len Number of bytes to compare
 * @return true if buffers match
 */
bool constantTimeCompare(const uint8_t* lhs, const uint8_t* rhs, size_t len);

/**
 * @brief Generate an ECDSA P-256 key pair
 *
 * @param privKey Private key output buffer (32 bytes)
 * @param pubKey Public key output buffer (65 bytes, uncompressed form 0x04 || X || Y)
 * @return Error::Success on success
 */
Error ecdsaP256GenerateKeyPair(uint8_t* privKey, uint8_t* pubKey);

/**
 * @brief Sign with ECDSA P-256
 *
 * Computes a SHA-256 hash and generates an ECDSA signature.
 * The signature is encoded in DER format.
 *
 * @param privKey Private key (32 bytes)
 * @param data Data to sign
 * @param dataLen Data length
 * @param sig Signature output buffer (max 72 bytes)
 * @param sigLen Stores the actual signature size
 * @return Error::Success on success
 */
Error ecdsaP256Sign(const uint8_t* privKey, const uint8_t* data, size_t dataLen, uint8_t* sig,
                    size_t* sigLen);

/**
 * @brief Verify an ECDSA P-256 signature
 *
 * @param pubKey Public key (65 bytes, uncompressed form)
 * @param data Data that was signed
 * @param dataLen Data length
 * @param sig Signature (DER format)
 * @param sigLen Signature length
 * @return true if the signature is valid
 */
bool ecdsaP256Verify(const uint8_t* pubKey, const uint8_t* data, size_t dataLen, const uint8_t* sig,
                     size_t sigLen);

}  // namespace ndn::crypto
