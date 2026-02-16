/**
 * @file test_signature.cpp
 * @brief NDN signature function tests
 */

#include "ndn/crypto.hpp"
#include "ndn/data.hpp"
#include "ndn/interest.hpp"
#include "ndn/signature.hpp"

#include <cstring>

#include "unity.h"

// =============================================================================
// Crypto utility tests
// =============================================================================

void test_crypto_sha256_basic(void) {
    // SHA-256 digest of "hello" (known value)
    const uint8_t input[] = "hello";
    uint8_t output[ndn::SHA256_DIGEST_SIZE];

    ndn::Error err = ndn::crypto::sha256(input, 5, output);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    // SHA-256 of "hello": 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    const uint8_t expected[] = {0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b,
                                0x2a, 0xc5, 0xb9, 0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7,
                                0x42, 0x5e, 0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24};
    TEST_ASSERT_EQUAL_MEMORY(expected, output, ndn::SHA256_DIGEST_SIZE);
}

void test_crypto_sha256_empty_input(void) {
    // SHA-256 of empty input
    uint8_t output[ndn::SHA256_DIGEST_SIZE];

    ndn::Error err = ndn::crypto::sha256(reinterpret_cast<const uint8_t*>(""), 0, output);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    // SHA-256 of empty string: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const uint8_t expected[] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
                                0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
                                0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    TEST_ASSERT_EQUAL_MEMORY(expected, output, ndn::SHA256_DIGEST_SIZE);
}

void test_crypto_hmac_sha256_basic(void) {
    const uint8_t key[] = "key";
    const uint8_t data[] = "The quick brown fox jumps over the lazy dog";
    uint8_t output[ndn::HMAC_SHA256_SIZE];

    ndn::Error err = ndn::crypto::hmacSha256(key, 3, data, sizeof(data) - 1, output);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    // HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog")
    // = f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
    const uint8_t expected[] = {0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 0xb1, 0x32, 0x98,
                                0xe6, 0xaa, 0x6f, 0xb1, 0x43, 0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46,
                                0x17, 0x59, 0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8};
    TEST_ASSERT_EQUAL_MEMORY(expected, output, ndn::HMAC_SHA256_SIZE);
}

void test_crypto_constant_time_compare_equal(void) {
    const uint8_t a[] = {0x01, 0x02, 0x03, 0x04};
    const uint8_t b[] = {0x01, 0x02, 0x03, 0x04};

    TEST_ASSERT_TRUE(ndn::crypto::constantTimeCompare(a, b, 4));
}

void test_crypto_constant_time_compare_not_equal(void) {
    const uint8_t a[] = {0x01, 0x02, 0x03, 0x04};
    const uint8_t b[] = {0x01, 0x02, 0x03, 0x05};

    TEST_ASSERT_FALSE(ndn::crypto::constantTimeCompare(a, b, 4));
}

void test_crypto_constant_time_compare_first_byte_differs(void) {
    const uint8_t a[] = {0x00, 0x02, 0x03, 0x04};
    const uint8_t b[] = {0xFF, 0x02, 0x03, 0x04};

    TEST_ASSERT_FALSE(ndn::crypto::constantTimeCompare(a, b, 4));
}

// =============================================================================
// SignatureType tests
// =============================================================================

void test_SignatureType_values(void) {
    TEST_ASSERT_EQUAL(0, static_cast<uint8_t>(ndn::SignatureType::DigestSha256));
    TEST_ASSERT_EQUAL(1, static_cast<uint8_t>(ndn::SignatureType::SignatureSha256WithRsa));
    TEST_ASSERT_EQUAL(3, static_cast<uint8_t>(ndn::SignatureType::SignatureSha256WithEcdsa));
    TEST_ASSERT_EQUAL(4, static_cast<uint8_t>(ndn::SignatureType::SignatureHmacWithSha256));
    TEST_ASSERT_EQUAL(5, static_cast<uint8_t>(ndn::SignatureType::SignatureEd25519));
}

void test_SignatureType_to_string(void) {
    TEST_ASSERT_EQUAL_STRING("DigestSha256",
                             ndn::signatureTypeToString(ndn::SignatureType::DigestSha256));
    TEST_ASSERT_EQUAL_STRING(
        "SignatureHmacWithSha256",
        ndn::signatureTypeToString(ndn::SignatureType::SignatureHmacWithSha256));
}

// =============================================================================
// Data signature - DigestSha256 tests
// =============================================================================

void test_Data_default_signature_type(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::SignatureType::DigestSha256, data.signatureType());
    TEST_ASSERT_FALSE(data.hasSignature());
    TEST_ASSERT_EQUAL(0, data.signatureValueSize());
}

void test_Data_signWithDigestSha256_basic(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test/data"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("hello world"));

    ndn::Error err = data.signWithDigestSha256();
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_EQUAL(ndn::SignatureType::DigestSha256, data.signatureType());
    TEST_ASSERT_TRUE(data.hasSignature());
    TEST_ASSERT_EQUAL(ndn::SHA256_DIGEST_SIZE, data.signatureValueSize());
}

void test_Data_verifyDigestSha256_valid(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test/data"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("hello world"));

    TEST_ASSERT_EQUAL(ndn::Error::Success, data.signWithDigestSha256());
    TEST_ASSERT_TRUE(data.verifyDigestSha256());
}

void test_Data_verifyDigestSha256_after_content_change_fails(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test/data"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("original"));

    TEST_ASSERT_EQUAL(ndn::Error::Success, data.signWithDigestSha256());
    TEST_ASSERT_TRUE(data.verifyDigestSha256());

    // Modify content
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("modified"));

    // Signature becomes invalid
    TEST_ASSERT_FALSE(data.verifyDigestSha256());
}

void test_Data_signWithDigestSha256_without_content(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/empty/content"));
    // No content

    ndn::Error err = data.signWithDigestSha256();
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_TRUE(data.verifyDigestSha256());
}

void test_Data_signWithDigestSha256_with_freshness(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("data"));
    data.setFreshnessPeriod(10000);

    TEST_ASSERT_EQUAL(ndn::Error::Success, data.signWithDigestSha256());
    TEST_ASSERT_TRUE(data.verifyDigestSha256());
}

// =============================================================================
// Data signature - HMAC-SHA256 tests
// =============================================================================

void test_Data_signWithHmac_basic(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test/hmac"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("secret data"));

    const uint8_t key[] = "my-secret-key-123";
    ndn::Error err = data.signWithHmac(key, sizeof(key) - 1);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_EQUAL(ndn::SignatureType::SignatureHmacWithSha256, data.signatureType());
    TEST_ASSERT_TRUE(data.hasSignature());
    TEST_ASSERT_EQUAL(ndn::HMAC_SHA256_SIZE, data.signatureValueSize());
}

void test_Data_verifyHmac_valid(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test/hmac"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("secret data"));

    const uint8_t key[] = "my-secret-key-123";
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.signWithHmac(key, sizeof(key) - 1));
    TEST_ASSERT_TRUE(data.verifyHmac(key, sizeof(key) - 1));
}

void test_Data_verifyHmac_wrong_key_fails(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test/hmac"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("secret data"));

    const uint8_t key1[] = "correct-key";
    const uint8_t key2[] = "wrong-key!!";

    TEST_ASSERT_EQUAL(ndn::Error::Success, data.signWithHmac(key1, sizeof(key1) - 1));

    // Verify with correct key
    TEST_ASSERT_TRUE(data.verifyHmac(key1, sizeof(key1) - 1));

    // Verify with wrong key
    TEST_ASSERT_FALSE(data.verifyHmac(key2, sizeof(key2) - 1));
}

void test_Data_verifyHmac_after_content_change_fails(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test/hmac"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("original"));

    const uint8_t key[] = "secret-key";
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.signWithHmac(key, sizeof(key) - 1));
    TEST_ASSERT_TRUE(data.verifyHmac(key, sizeof(key) - 1));

    // Modify content
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("tampered"));

    // Signature becomes invalid
    TEST_ASSERT_FALSE(data.verifyHmac(key, sizeof(key) - 1));
}

void test_Data_signWithHmac_null_key_fails(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("data"));

    ndn::Error err = data.signWithHmac(nullptr, 0);
    TEST_ASSERT_EQUAL(ndn::Error::InvalidParam, err);
}

void test_Data_verifyHmac_null_key_fails(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("data"));

    const uint8_t key[] = "key";
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.signWithHmac(key, sizeof(key) - 1));

    TEST_ASSERT_FALSE(data.verifyHmac(nullptr, 0));
}

// =============================================================================
// Data signature encode/decode tests
// =============================================================================

void test_Data_signature_encode_decode_roundtrip_digest(void) {
    ndn::Data original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/signed"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setContent("signed content"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.signWithDigestSha256());

    // Encode
    uint8_t buf[256];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    // Decode
    auto decoded = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    // Check signature type and size
    TEST_ASSERT_EQUAL(ndn::SignatureType::DigestSha256, decoded.value.signatureType());
    TEST_ASSERT_EQUAL(ndn::SHA256_DIGEST_SIZE, decoded.value.signatureValueSize());

    // Signature value matches
    TEST_ASSERT_EQUAL_MEMORY(original.signatureValue(), decoded.value.signatureValue(),
                             ndn::SHA256_DIGEST_SIZE);

    // Verification succeeds
    TEST_ASSERT_TRUE(decoded.value.verifyDigestSha256());
}

void test_Data_signature_encode_decode_roundtrip_hmac(void) {
    ndn::Data original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/hmac/signed"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setContent("hmac content"));

    const uint8_t key[] = "hmac-key-for-test";
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.signWithHmac(key, sizeof(key) - 1));

    // Encode
    uint8_t buf[256];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    // Decode
    auto decoded = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    // Check signature type and size
    TEST_ASSERT_EQUAL(ndn::SignatureType::SignatureHmacWithSha256, decoded.value.signatureType());
    TEST_ASSERT_EQUAL(ndn::HMAC_SHA256_SIZE, decoded.value.signatureValueSize());

    // Signature value matches
    TEST_ASSERT_EQUAL_MEMORY(original.signatureValue(), decoded.value.signatureValue(),
                             ndn::HMAC_SHA256_SIZE);

    // Verification succeeds
    TEST_ASSERT_TRUE(decoded.value.verifyHmac(key, sizeof(key) - 1));
}

void test_Data_signature_setSignatureType(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::SignatureType::DigestSha256, data.signatureType());

    data.setSignatureType(ndn::SignatureType::SignatureHmacWithSha256);
    TEST_ASSERT_EQUAL(ndn::SignatureType::SignatureHmacWithSha256, data.signatureType());
}

void test_Data_verifyDigestSha256_wrong_type_fails(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("data"));

    const uint8_t key[] = "key";
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.signWithHmac(key, sizeof(key) - 1));

    // Verifying HMAC-signed Data with Digest should fail
    TEST_ASSERT_FALSE(data.verifyDigestSha256());
}

void test_Data_verifyHmac_wrong_type_fails(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("data"));

    TEST_ASSERT_EQUAL(ndn::Error::Success, data.signWithDigestSha256());

    const uint8_t key[] = "key";
    // Verifying Digest-signed Data with HMAC should fail
    TEST_ASSERT_FALSE(data.verifyHmac(key, sizeof(key) - 1));
}

// =============================================================================
// Interest signature - DigestSha256 tests
// =============================================================================

void test_Interest_default_not_signed(void) {
    ndn::Interest interest;
    TEST_ASSERT_FALSE(interest.isSigned());
    TEST_ASSERT_EQUAL(0, interest.signatureValueSize());
}

void test_Interest_signWithDigestSha256_basic(void) {
    ndn::Interest interest;
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.setName("/test/interest"));

    ndn::Error err = interest.signWithDigestSha256();
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_TRUE(interest.isSigned());
    TEST_ASSERT_EQUAL(ndn::SignatureType::DigestSha256, interest.signatureType());
    TEST_ASSERT_EQUAL(ndn::SHA256_DIGEST_SIZE, interest.signatureValueSize());
    TEST_ASSERT_NOT_NULL(interest.signatureNonce());
    TEST_ASSERT_TRUE(interest.signatureTime().has_value());
}

void test_Interest_verifyDigestSha256_valid(void) {
    ndn::Interest interest;
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.setName("/test/interest"));

    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.signWithDigestSha256());
    TEST_ASSERT_TRUE(interest.verifyDigestSha256());
}

void test_Interest_verifyDigestSha256_after_name_change_fails(void) {
    ndn::Interest interest;
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.setName("/original/name"));

    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.signWithDigestSha256());
    TEST_ASSERT_TRUE(interest.verifyDigestSha256());

    // Modify Name
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.setName("/modified/name"));

    // Signature becomes invalid
    TEST_ASSERT_FALSE(interest.verifyDigestSha256());
}

void test_Interest_signWithDigestSha256_with_app_params(void) {
    ndn::Interest interest;
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.setName("/test"));

    const uint8_t params[] = {0x01, 0x02, 0x03};
    interest.setApplicationParameters(params, sizeof(params));

    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.signWithDigestSha256());
    TEST_ASSERT_TRUE(interest.verifyDigestSha256());
}

// =============================================================================
// Interest signature - HMAC-SHA256 tests
// =============================================================================

void test_Interest_signWithHmac_basic(void) {
    ndn::Interest interest;
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.setName("/test/hmac"));

    const uint8_t key[] = "secret-key";
    ndn::Error err = interest.signWithHmac(key, sizeof(key) - 1);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_TRUE(interest.isSigned());
    TEST_ASSERT_EQUAL(ndn::SignatureType::SignatureHmacWithSha256, interest.signatureType());
    TEST_ASSERT_EQUAL(ndn::HMAC_SHA256_SIZE, interest.signatureValueSize());
}

void test_Interest_verifyHmac_valid(void) {
    ndn::Interest interest;
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.setName("/test/hmac"));

    const uint8_t key[] = "secret-key";
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.signWithHmac(key, sizeof(key) - 1));
    TEST_ASSERT_TRUE(interest.verifyHmac(key, sizeof(key) - 1));
}

void test_Interest_verifyHmac_wrong_key_fails(void) {
    ndn::Interest interest;
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.setName("/test/hmac"));

    const uint8_t key1[] = "correct-key";
    const uint8_t key2[] = "wrong-key!!";

    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.signWithHmac(key1, sizeof(key1) - 1));

    TEST_ASSERT_TRUE(interest.verifyHmac(key1, sizeof(key1) - 1));
    TEST_ASSERT_FALSE(interest.verifyHmac(key2, sizeof(key2) - 1));
}

void test_Interest_signWithHmac_null_key_fails(void) {
    ndn::Interest interest;
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.setName("/test"));

    ndn::Error err = interest.signWithHmac(nullptr, 0);
    TEST_ASSERT_EQUAL(ndn::Error::InvalidParam, err);
}

// =============================================================================
// Interest signature encode/decode tests
// =============================================================================

void test_Interest_signature_encode_decode_roundtrip_digest(void) {
    ndn::Interest original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/signed"));
    original.generateNonce();
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.signWithDigestSha256());

    // Encode
    uint8_t buf[256];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    // Decode
    auto decoded = ndn::Interest::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    // Check signature type and size
    TEST_ASSERT_TRUE(decoded.value.isSigned());
    TEST_ASSERT_EQUAL(ndn::SignatureType::DigestSha256, decoded.value.signatureType());
    TEST_ASSERT_EQUAL(ndn::SHA256_DIGEST_SIZE, decoded.value.signatureValueSize());

    // Signature value matches
    TEST_ASSERT_EQUAL_MEMORY(original.signatureValue(), decoded.value.signatureValue(),
                             ndn::SHA256_DIGEST_SIZE);

    // Signature nonce matches
    TEST_ASSERT_NOT_NULL(decoded.value.signatureNonce());

    // Verification succeeds
    TEST_ASSERT_TRUE(decoded.value.verifyDigestSha256());
}

void test_Interest_signature_encode_decode_roundtrip_hmac(void) {
    ndn::Interest original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/hmac/signed"));
    original.generateNonce();

    const uint8_t key[] = "hmac-key-for-test";
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.signWithHmac(key, sizeof(key) - 1));

    // Encode
    uint8_t buf[256];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    // Decode
    auto decoded = ndn::Interest::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    // Check signature type and size
    TEST_ASSERT_TRUE(decoded.value.isSigned());
    TEST_ASSERT_EQUAL(ndn::SignatureType::SignatureHmacWithSha256, decoded.value.signatureType());
    TEST_ASSERT_EQUAL(ndn::HMAC_SHA256_SIZE, decoded.value.signatureValueSize());

    // Verification succeeds
    TEST_ASSERT_TRUE(decoded.value.verifyHmac(key, sizeof(key) - 1));
}

void test_Interest_unsigned_encode_decode_roundtrip(void) {
    // Unsigned Interest works as before
    ndn::Interest original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/unsigned"));
    original.generateNonce();

    uint8_t buf[128];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Interest::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    TEST_ASSERT_FALSE(decoded.value.isSigned());
    TEST_ASSERT_TRUE(original.name().equals(decoded.value.name()));
}

// =============================================================================
// ECDSA P-256 crypto tests
// =============================================================================

void test_crypto_ecdsa_generate_key_pair(void) {
    uint8_t privKey[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey[ndn::ECDSA_P256_PUBKEY_SIZE];

    ndn::Error err = ndn::crypto::ecdsaP256GenerateKeyPair(privKey, pubKey);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    // Public key is in uncompressed form, starting with 0x04
    TEST_ASSERT_EQUAL(0x04, pubKey[0]);
}

void test_crypto_ecdsa_sign_verify(void) {
    uint8_t privKey[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey[ndn::ECDSA_P256_PUBKEY_SIZE];

    ndn::Error err = ndn::crypto::ecdsaP256GenerateKeyPair(privKey, pubKey);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    const uint8_t message[] = "Hello, ECDSA signature test!";
    uint8_t sig[ndn::ECDSA_P256_SIG_MAX_SIZE];
    size_t sigLen = 0;

    // Sign
    err = ndn::crypto::ecdsaP256Sign(privKey, message, sizeof(message) - 1, sig, &sigLen);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_TRUE(sigLen > 0);
    TEST_ASSERT_TRUE(sigLen <= ndn::ECDSA_P256_SIG_MAX_SIZE);

    // Verify
    bool valid = ndn::crypto::ecdsaP256Verify(pubKey, message, sizeof(message) - 1, sig, sigLen);
    TEST_ASSERT_TRUE(valid);
}

void test_crypto_ecdsa_verify_wrong_message_fails(void) {
    uint8_t privKey[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey[ndn::ECDSA_P256_PUBKEY_SIZE];

    ndn::Error err = ndn::crypto::ecdsaP256GenerateKeyPair(privKey, pubKey);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    const uint8_t message1[] = "Original message";
    const uint8_t message2[] = "Tampered message";
    uint8_t sig[ndn::ECDSA_P256_SIG_MAX_SIZE];
    size_t sigLen = 0;

    // Sign message1
    err = ndn::crypto::ecdsaP256Sign(privKey, message1, sizeof(message1) - 1, sig, &sigLen);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    // Verify with message2 (should fail)
    bool valid = ndn::crypto::ecdsaP256Verify(pubKey, message2, sizeof(message2) - 1, sig, sigLen);
    TEST_ASSERT_FALSE(valid);
}

void test_crypto_ecdsa_verify_wrong_key_fails(void) {
    uint8_t privKey1[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey1[ndn::ECDSA_P256_PUBKEY_SIZE];
    uint8_t privKey2[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey2[ndn::ECDSA_P256_PUBKEY_SIZE];

    // Generate two key pairs
    ndn::Error err = ndn::crypto::ecdsaP256GenerateKeyPair(privKey1, pubKey1);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    err = ndn::crypto::ecdsaP256GenerateKeyPair(privKey2, pubKey2);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    const uint8_t message[] = "Test message";
    uint8_t sig[ndn::ECDSA_P256_SIG_MAX_SIZE];
    size_t sigLen = 0;

    // Sign with privKey1
    err = ndn::crypto::ecdsaP256Sign(privKey1, message, sizeof(message) - 1, sig, &sigLen);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    // Verify with pubKey1 (success)
    TEST_ASSERT_TRUE(
        ndn::crypto::ecdsaP256Verify(pubKey1, message, sizeof(message) - 1, sig, sigLen));

    // Verify with pubKey2 (failure)
    TEST_ASSERT_FALSE(
        ndn::crypto::ecdsaP256Verify(pubKey2, message, sizeof(message) - 1, sig, sigLen));
}

// =============================================================================
// Data signature - ECDSA P-256 tests
// =============================================================================

void test_Data_signWithEcdsa_basic(void) {
    uint8_t privKey[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey[ndn::ECDSA_P256_PUBKEY_SIZE];
    TEST_ASSERT_EQUAL(ndn::Error::Success, ndn::crypto::ecdsaP256GenerateKeyPair(privKey, pubKey));

    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test/ecdsa"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("ecdsa signed data"));

    ndn::Error err = data.signWithEcdsa(privKey);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_EQUAL(ndn::SignatureType::SignatureSha256WithEcdsa, data.signatureType());
    TEST_ASSERT_TRUE(data.hasSignature());
    TEST_ASSERT_TRUE(data.signatureValueSize() > 0);
    TEST_ASSERT_TRUE(data.signatureValueSize() <= ndn::ECDSA_P256_SIG_MAX_SIZE);
}

void test_Data_verifyEcdsa_valid(void) {
    uint8_t privKey[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey[ndn::ECDSA_P256_PUBKEY_SIZE];
    TEST_ASSERT_EQUAL(ndn::Error::Success, ndn::crypto::ecdsaP256GenerateKeyPair(privKey, pubKey));

    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test/ecdsa"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("ecdsa signed data"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.signWithEcdsa(privKey));

    TEST_ASSERT_TRUE(data.verifyEcdsa(pubKey));
}

void test_Data_verifyEcdsa_wrong_key_fails(void) {
    uint8_t privKey1[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey1[ndn::ECDSA_P256_PUBKEY_SIZE];
    uint8_t privKey2[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey2[ndn::ECDSA_P256_PUBKEY_SIZE];

    TEST_ASSERT_EQUAL(ndn::Error::Success,
                      ndn::crypto::ecdsaP256GenerateKeyPair(privKey1, pubKey1));
    TEST_ASSERT_EQUAL(ndn::Error::Success,
                      ndn::crypto::ecdsaP256GenerateKeyPair(privKey2, pubKey2));

    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test/ecdsa"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("data"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.signWithEcdsa(privKey1));

    TEST_ASSERT_TRUE(data.verifyEcdsa(pubKey1));
    TEST_ASSERT_FALSE(data.verifyEcdsa(pubKey2));
}

void test_Data_verifyEcdsa_after_content_change_fails(void) {
    uint8_t privKey[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey[ndn::ECDSA_P256_PUBKEY_SIZE];
    TEST_ASSERT_EQUAL(ndn::Error::Success, ndn::crypto::ecdsaP256GenerateKeyPair(privKey, pubKey));

    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test/ecdsa"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("original"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.signWithEcdsa(privKey));
    TEST_ASSERT_TRUE(data.verifyEcdsa(pubKey));

    // Modify content
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("tampered"));
    TEST_ASSERT_FALSE(data.verifyEcdsa(pubKey));
}

void test_Data_signature_encode_decode_roundtrip_ecdsa(void) {
    uint8_t privKey[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey[ndn::ECDSA_P256_PUBKEY_SIZE];
    TEST_ASSERT_EQUAL(ndn::Error::Success, ndn::crypto::ecdsaP256GenerateKeyPair(privKey, pubKey));

    ndn::Data original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/ecdsa/roundtrip"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setContent("ecdsa content"));

    // Set KeyLocator
    auto keyNameResult = ndn::Name::fromUri("/key/ecdsa-001");
    TEST_ASSERT_TRUE(keyNameResult.ok());
    original.setKeyLocator(keyNameResult.value);

    TEST_ASSERT_EQUAL(ndn::Error::Success, original.signWithEcdsa(privKey));

    // Encode
    uint8_t buf[512];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    // Decode
    auto decoded = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    // Check signature type
    TEST_ASSERT_EQUAL(ndn::SignatureType::SignatureSha256WithEcdsa, decoded.value.signatureType());

    // Check KeyLocator
    TEST_ASSERT_TRUE(decoded.value.hasKeyLocator());
    TEST_ASSERT_TRUE(decoded.value.keyLocator()->equals(keyNameResult.value));

    // Verification succeeds
    TEST_ASSERT_TRUE(decoded.value.verifyEcdsa(pubKey));
}

// =============================================================================
// Interest signature - ECDSA P-256 tests
// =============================================================================

void test_Interest_signWithEcdsa_basic(void) {
    uint8_t privKey[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey[ndn::ECDSA_P256_PUBKEY_SIZE];
    TEST_ASSERT_EQUAL(ndn::Error::Success, ndn::crypto::ecdsaP256GenerateKeyPair(privKey, pubKey));

    ndn::Interest interest;
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.setName("/test/ecdsa"));

    ndn::Error err = interest.signWithEcdsa(privKey);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_TRUE(interest.isSigned());
    TEST_ASSERT_EQUAL(ndn::SignatureType::SignatureSha256WithEcdsa, interest.signatureType());
    TEST_ASSERT_TRUE(interest.signatureValueSize() > 0);
    TEST_ASSERT_NOT_NULL(interest.signatureNonce());
    TEST_ASSERT_TRUE(interest.signatureTime().has_value());
}

void test_Interest_verifyEcdsa_valid(void) {
    uint8_t privKey[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey[ndn::ECDSA_P256_PUBKEY_SIZE];
    TEST_ASSERT_EQUAL(ndn::Error::Success, ndn::crypto::ecdsaP256GenerateKeyPair(privKey, pubKey));

    ndn::Interest interest;
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.setName("/test/ecdsa"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.signWithEcdsa(privKey));

    TEST_ASSERT_TRUE(interest.verifyEcdsa(pubKey));
}

void test_Interest_verifyEcdsa_wrong_key_fails(void) {
    uint8_t privKey1[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey1[ndn::ECDSA_P256_PUBKEY_SIZE];
    uint8_t privKey2[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey2[ndn::ECDSA_P256_PUBKEY_SIZE];

    TEST_ASSERT_EQUAL(ndn::Error::Success,
                      ndn::crypto::ecdsaP256GenerateKeyPair(privKey1, pubKey1));
    TEST_ASSERT_EQUAL(ndn::Error::Success,
                      ndn::crypto::ecdsaP256GenerateKeyPair(privKey2, pubKey2));

    ndn::Interest interest;
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.setName("/test/ecdsa"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.signWithEcdsa(privKey1));

    TEST_ASSERT_TRUE(interest.verifyEcdsa(pubKey1));
    TEST_ASSERT_FALSE(interest.verifyEcdsa(pubKey2));
}

void test_Interest_signature_encode_decode_roundtrip_ecdsa(void) {
    uint8_t privKey[ndn::ECDSA_P256_PRIVKEY_SIZE];
    uint8_t pubKey[ndn::ECDSA_P256_PUBKEY_SIZE];
    TEST_ASSERT_EQUAL(ndn::Error::Success, ndn::crypto::ecdsaP256GenerateKeyPair(privKey, pubKey));

    ndn::Interest original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/ecdsa/roundtrip"));
    original.generateNonce();

    // Set KeyLocator
    auto keyNameResult = ndn::Name::fromUri("/key/ecdsa-interest");
    TEST_ASSERT_TRUE(keyNameResult.ok());
    original.setKeyLocator(keyNameResult.value);

    TEST_ASSERT_EQUAL(ndn::Error::Success, original.signWithEcdsa(privKey));

    // Encode
    uint8_t buf[512];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    // Decode
    auto decoded = ndn::Interest::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    // Check signature type
    TEST_ASSERT_TRUE(decoded.value.isSigned());
    TEST_ASSERT_EQUAL(ndn::SignatureType::SignatureSha256WithEcdsa, decoded.value.signatureType());

    // Check KeyLocator
    TEST_ASSERT_TRUE(decoded.value.hasKeyLocator());
    TEST_ASSERT_TRUE(decoded.value.keyLocator()->equals(keyNameResult.value));

    // Verification succeeds
    TEST_ASSERT_TRUE(decoded.value.verifyEcdsa(pubKey));
}

// =============================================================================
// Test runner
// =============================================================================

void run_signature_tests(void) {
    // Crypto utility tests
    RUN_TEST(test_crypto_sha256_basic);
    RUN_TEST(test_crypto_sha256_empty_input);
    RUN_TEST(test_crypto_hmac_sha256_basic);
    RUN_TEST(test_crypto_constant_time_compare_equal);
    RUN_TEST(test_crypto_constant_time_compare_not_equal);
    RUN_TEST(test_crypto_constant_time_compare_first_byte_differs);

    // SignatureType tests
    RUN_TEST(test_SignatureType_values);
    RUN_TEST(test_SignatureType_to_string);

    // Data signature - DigestSha256 tests
    RUN_TEST(test_Data_default_signature_type);
    RUN_TEST(test_Data_signWithDigestSha256_basic);
    RUN_TEST(test_Data_verifyDigestSha256_valid);
    RUN_TEST(test_Data_verifyDigestSha256_after_content_change_fails);
    RUN_TEST(test_Data_signWithDigestSha256_without_content);
    RUN_TEST(test_Data_signWithDigestSha256_with_freshness);

    // Data signature - HMAC-SHA256 tests
    RUN_TEST(test_Data_signWithHmac_basic);
    RUN_TEST(test_Data_verifyHmac_valid);
    RUN_TEST(test_Data_verifyHmac_wrong_key_fails);
    RUN_TEST(test_Data_verifyHmac_after_content_change_fails);
    RUN_TEST(test_Data_signWithHmac_null_key_fails);
    RUN_TEST(test_Data_verifyHmac_null_key_fails);

    // Data signature encode/decode tests
    RUN_TEST(test_Data_signature_encode_decode_roundtrip_digest);
    RUN_TEST(test_Data_signature_encode_decode_roundtrip_hmac);
    RUN_TEST(test_Data_signature_setSignatureType);
    RUN_TEST(test_Data_verifyDigestSha256_wrong_type_fails);
    RUN_TEST(test_Data_verifyHmac_wrong_type_fails);

    // Interest signature - DigestSha256 tests
    RUN_TEST(test_Interest_default_not_signed);
    RUN_TEST(test_Interest_signWithDigestSha256_basic);
    RUN_TEST(test_Interest_verifyDigestSha256_valid);
    RUN_TEST(test_Interest_verifyDigestSha256_after_name_change_fails);
    RUN_TEST(test_Interest_signWithDigestSha256_with_app_params);

    // Interest signature - HMAC-SHA256 tests
    RUN_TEST(test_Interest_signWithHmac_basic);
    RUN_TEST(test_Interest_verifyHmac_valid);
    RUN_TEST(test_Interest_verifyHmac_wrong_key_fails);
    RUN_TEST(test_Interest_signWithHmac_null_key_fails);

    // Interest signature encode/decode tests
    RUN_TEST(test_Interest_signature_encode_decode_roundtrip_digest);
    RUN_TEST(test_Interest_signature_encode_decode_roundtrip_hmac);
    RUN_TEST(test_Interest_unsigned_encode_decode_roundtrip);

    // ECDSA P-256 crypto tests
    RUN_TEST(test_crypto_ecdsa_generate_key_pair);
    RUN_TEST(test_crypto_ecdsa_sign_verify);
    RUN_TEST(test_crypto_ecdsa_verify_wrong_message_fails);
    RUN_TEST(test_crypto_ecdsa_verify_wrong_key_fails);

    // Data signature - ECDSA P-256 tests
    RUN_TEST(test_Data_signWithEcdsa_basic);
    RUN_TEST(test_Data_verifyEcdsa_valid);
    RUN_TEST(test_Data_verifyEcdsa_wrong_key_fails);
    RUN_TEST(test_Data_verifyEcdsa_after_content_change_fails);
    RUN_TEST(test_Data_signature_encode_decode_roundtrip_ecdsa);

    // Interest signature - ECDSA P-256 tests
    RUN_TEST(test_Interest_signWithEcdsa_basic);
    RUN_TEST(test_Interest_verifyEcdsa_valid);
    RUN_TEST(test_Interest_verifyEcdsa_wrong_key_fails);
    RUN_TEST(test_Interest_signature_encode_decode_roundtrip_ecdsa);
}
