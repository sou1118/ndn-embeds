/**
 * @file crypto.cpp
 * @brief NDN cryptographic utility implementation
 */

#include "ndn/crypto.hpp"
#include "ndn/signature.hpp"

#include <cstring>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

namespace ndn::crypto {

Error sha256(const uint8_t* data, size_t len, uint8_t* out) {
    if (data == nullptr || out == nullptr) {
        return Error::InvalidParam;
    }

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    int ret = mbedtls_sha256_starts(&ctx, 0);  // 0 = SHA-256 (not SHA-224)
    if (ret != 0) {
        mbedtls_sha256_free(&ctx);
        return Error::DecodeFailed;
    }

    ret = mbedtls_sha256_update(&ctx, data, len);
    if (ret != 0) {
        mbedtls_sha256_free(&ctx);
        return Error::DecodeFailed;
    }

    ret = mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);

    return (ret == 0) ? Error::Success : Error::DecodeFailed;
}

Error hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen,
                 uint8_t* out) {
    if (key == nullptr || data == nullptr || out == nullptr) {
        return Error::InvalidParam;
    }

    const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mdInfo == nullptr) {
        return Error::DecodeFailed;
    }

    int ret = mbedtls_md_hmac(mdInfo, key, keyLen, data, dataLen, out);
    return (ret == 0) ? Error::Success : Error::DecodeFailed;
}

bool constantTimeCompare(const uint8_t* lhs, const uint8_t* rhs, size_t len) {
    if (lhs == nullptr || rhs == nullptr) {
        return false;
    }

    volatile uint8_t result = 0;
    for (size_t i = 0; i < len; ++i) {
        result |= lhs[i] ^ rhs[i];
    }
    return result == 0;
}

Error ecdsaP256GenerateKeyPair(uint8_t* privKey, uint8_t* pubKey) {
    if (privKey == nullptr || pubKey == nullptr) {
        return Error::InvalidParam;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctrDrbg;
    mbedtls_ecdsa_context ecdsa;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctrDrbg);
    mbedtls_ecdsa_init(&ecdsa);

    Error err = Error::Success;
    size_t pubKeyLen = 0;
    const char* pers = "ndn_ecdsa_keygen";

    // Initialize random number generator
    int ret = mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy,
                                    reinterpret_cast<const unsigned char*>(pers), strlen(pers));
    if (ret != 0) {
        err = Error::DecodeFailed;
        goto cleanup;
    }

    // Generate P-256 key pair
    ret = mbedtls_ecdsa_genkey(&ecdsa, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &ctrDrbg);
    if (ret != 0) {
        err = Error::DecodeFailed;
        goto cleanup;
    }

    // Export private key (32 bytes, big-endian)
    ret = mbedtls_ecp_write_key_ext(&ecdsa, &pubKeyLen, privKey, ECDSA_P256_PRIVKEY_SIZE);
    if (ret != 0) {
        err = Error::DecodeFailed;
        goto cleanup;
    }

    // Export public key (65 bytes, uncompressed format: 0x04 || X || Y)
    ret = mbedtls_ecp_write_public_key(&ecdsa, MBEDTLS_ECP_PF_UNCOMPRESSED, &pubKeyLen, pubKey,
                                       ECDSA_P256_PUBKEY_SIZE);
    if (ret != 0 || pubKeyLen != ECDSA_P256_PUBKEY_SIZE) {
        err = Error::DecodeFailed;
        goto cleanup;
    }

cleanup:
    mbedtls_ecdsa_free(&ecdsa);
    mbedtls_ctr_drbg_free(&ctrDrbg);
    mbedtls_entropy_free(&entropy);
    return err;
}

Error ecdsaP256Sign(const uint8_t* privKey, const uint8_t* data, size_t dataLen, uint8_t* sig,
                    size_t* sigLen) {
    if (privKey == nullptr || data == nullptr || sig == nullptr || sigLen == nullptr) {
        return Error::InvalidParam;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctrDrbg;
    mbedtls_ecdsa_context ecdsa;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctrDrbg);
    mbedtls_ecdsa_init(&ecdsa);

    Error err = Error::Success;
    uint8_t hash[SHA256_DIGEST_SIZE];
    const char* pers = "ndn_ecdsa_sign";

    // Initialize random number generator
    int ret = mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy,
                                    reinterpret_cast<const unsigned char*>(pers), strlen(pers));
    if (ret != 0) {
        err = Error::DecodeFailed;
        goto cleanup;
    }

    // Import private key (group is also set automatically)
    ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &ecdsa, privKey, ECDSA_P256_PRIVKEY_SIZE);
    if (ret != 0) {
        err = Error::DecodeFailed;
        goto cleanup;
    }

    // Compute SHA-256 hash of the data
    err = sha256(data, dataLen, hash);
    if (err != Error::Success) {
        goto cleanup;
    }

    // Generate ECDSA signature (DER format)
    ret = mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig,
                                        ECDSA_P256_SIG_MAX_SIZE, sigLen, mbedtls_ctr_drbg_random,
                                        &ctrDrbg);
    if (ret != 0) {
        err = Error::DecodeFailed;
        goto cleanup;
    }

cleanup:
    mbedtls_ecdsa_free(&ecdsa);
    mbedtls_ctr_drbg_free(&ctrDrbg);
    mbedtls_entropy_free(&entropy);
    return err;
}

bool ecdsaP256Verify(const uint8_t* pubKey, const uint8_t* data, size_t dataLen, const uint8_t* sig,
                     size_t sigLen) {
    if (pubKey == nullptr || data == nullptr || sig == nullptr || sigLen == 0) {
        return false;
    }

    mbedtls_ecdsa_context ecdsa;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;

    mbedtls_ecdsa_init(&ecdsa);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);

    bool valid = false;
    uint8_t hash[SHA256_DIGEST_SIZE];

    // Set up elliptic curve group
    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        goto cleanup;
    }

    // Load public key as a point (uncompressed format: 0x04 || X || Y)
    ret = mbedtls_ecp_point_read_binary(&grp, &Q, pubKey, ECDSA_P256_PUBKEY_SIZE);
    if (ret != 0) {
        goto cleanup;
    }

    // Set public key in the ECDSA context
    ret = mbedtls_ecp_set_public_key(MBEDTLS_ECP_DP_SECP256R1, &ecdsa, &Q);
    if (ret != 0) {
        goto cleanup;
    }

    // Compute SHA-256 hash of the data
    if (sha256(data, dataLen, hash) != Error::Success) {
        goto cleanup;
    }

    // Verify ECDSA signature
    ret = mbedtls_ecdsa_read_signature(&ecdsa, hash, sizeof(hash), sig, sigLen);
    valid = (ret == 0);

cleanup:
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecdsa_free(&ecdsa);
    return valid;
}

}  // namespace ndn::crypto
