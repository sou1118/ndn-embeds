/**
 * @file test_certificate.cpp
 * @brief NDN Certificate tests
 */

#include "ndn/certificate.hpp"
#include "ndn/tlv.hpp"

#include <cstring>

#include "unity.h"

// =============================================================================
// ValidityPeriod tests
// =============================================================================

void test_ValidityPeriod_setNotBefore_datetime(void) {
    ndn::ValidityPeriod vp;

    ndn::Error err = vp.setNotBefore(2024, 1, 15, 10, 30, 45);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    // "20240115T103045"
    TEST_ASSERT_EQUAL_MEMORY("20240115T103045", vp.notBefore(), 15);
}

void test_ValidityPeriod_setNotAfter_datetime(void) {
    ndn::ValidityPeriod vp;

    ndn::Error err = vp.setNotAfter(2025, 12, 31, 23, 59, 59);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    // "20251231T235959"
    TEST_ASSERT_EQUAL_MEMORY("20251231T235959", vp.notAfter(), 15);
}

void test_ValidityPeriod_setNotBefore_string(void) {
    ndn::ValidityPeriod vp;

    ndn::Error err = vp.setNotBefore("20240601T000000");
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_EQUAL_MEMORY("20240601T000000", vp.notBefore(), 15);
}

void test_ValidityPeriod_setNotBefore_invalid_string(void) {
    ndn::ValidityPeriod vp;

    // Too short
    TEST_ASSERT_EQUAL(ndn::Error::InvalidParam, vp.setNotBefore("20240601"));

    // Missing T
    TEST_ASSERT_EQUAL(ndn::Error::InvalidParam, vp.setNotBefore("20240601-000000"));

    // Non-digit
    TEST_ASSERT_EQUAL(ndn::Error::InvalidParam, vp.setNotBefore("2024060aT000000"));
}

void test_ValidityPeriod_fromStrings(void) {
    auto result = ndn::ValidityPeriod::fromStrings("20240101T000000", "20241231T235959");
    TEST_ASSERT_TRUE(result.ok());

    TEST_ASSERT_EQUAL_MEMORY("20240101T000000", result.value.notBefore(), 15);
    TEST_ASSERT_EQUAL_MEMORY("20241231T235959", result.value.notAfter(), 15);
}

void test_ValidityPeriod_fromStrings_invalid(void) {
    auto result = ndn::ValidityPeriod::fromStrings("invalid", "20241231T235959");
    TEST_ASSERT_FALSE(result.ok());
}

void test_ValidityPeriod_isValidAt_within_range(void) {
    ndn::ValidityPeriod vp;
    vp.setNotBefore(2024, 1, 1, 0, 0, 0);
    vp.setNotAfter(2024, 12, 31, 23, 59, 59);

    TEST_ASSERT_TRUE(vp.isValidAt("20240601T120000"));
    TEST_ASSERT_TRUE(vp.isValidAt("20240101T000000"));  // Exactly at start
    TEST_ASSERT_TRUE(vp.isValidAt("20241231T235959"));  // Exactly at end
}

void test_ValidityPeriod_isValidAt_before_range(void) {
    ndn::ValidityPeriod vp;
    vp.setNotBefore(2024, 6, 1, 0, 0, 0);
    vp.setNotAfter(2024, 12, 31, 23, 59, 59);

    TEST_ASSERT_FALSE(vp.isValidAt("20240531T235959"));  // Just before start
    TEST_ASSERT_FALSE(vp.isValidAt("20230101T000000"));  // Way before
}

void test_ValidityPeriod_isValidAt_after_range(void) {
    ndn::ValidityPeriod vp;
    vp.setNotBefore(2024, 1, 1, 0, 0, 0);
    vp.setNotAfter(2024, 6, 30, 23, 59, 59);

    TEST_ASSERT_FALSE(vp.isValidAt("20240701T000000"));  // Just after end
    TEST_ASSERT_FALSE(vp.isValidAt("20250101T000000"));  // Way after
}

void test_ValidityPeriod_encode_decode_roundtrip(void) {
    ndn::ValidityPeriod original;
    original.setNotBefore(2024, 3, 15, 8, 30, 0);
    original.setNotAfter(2025, 3, 15, 8, 30, 0);

    // Encode
    uint8_t buf[128];
    size_t len = 0;
    ndn::Error err = original.encode(buf, sizeof(buf), len);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_TRUE(len > 0);

    // Decode
    size_t bytesRead = 0;
    auto result = ndn::ValidityPeriod::fromWire(buf, len, &bytesRead);
    TEST_ASSERT_TRUE(result.ok());
    TEST_ASSERT_EQUAL(len, bytesRead);

    TEST_ASSERT_TRUE(original.equals(result.value));
}

void test_ValidityPeriod_equals(void) {
    ndn::ValidityPeriod vp1, vp2;

    vp1.setNotBefore(2024, 1, 1, 0, 0, 0);
    vp1.setNotAfter(2025, 1, 1, 0, 0, 0);

    vp2.setNotBefore(2024, 1, 1, 0, 0, 0);
    vp2.setNotAfter(2025, 1, 1, 0, 0, 0);

    TEST_ASSERT_TRUE(vp1.equals(vp2));

    vp2.setNotAfter(2025, 1, 2, 0, 0, 0);
    TEST_ASSERT_FALSE(vp1.equals(vp2));
}

// =============================================================================
// Certificate tests - Basic
// =============================================================================

void test_Certificate_default_constructor(void) {
    ndn::Certificate cert;

    TEST_ASSERT_EQUAL(0, cert.identityName().componentCount());
    TEST_ASSERT_EQUAL(0, cert.keyIdSize());
    TEST_ASSERT_EQUAL(0, cert.issuerIdSize());
    TEST_ASSERT_EQUAL(0, cert.version());
    TEST_ASSERT_EQUAL(0, cert.publicKeySize());
    TEST_ASSERT_EQUAL(ndn::SignatureType::DigestSha256, cert.signatureType());
}

void test_Certificate_setIdentityName(void) {
    ndn::Certificate cert;

    ndn::Error err = cert.setIdentityName("/example/user");
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_EQUAL(2, cert.identityName().componentCount());
}

void test_Certificate_setKeyId(void) {
    ndn::Certificate cert;

    const uint8_t keyId[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    ndn::Error err = cert.setKeyId(keyId, sizeof(keyId));
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_EQUAL(8, cert.keyIdSize());
    TEST_ASSERT_EQUAL_MEMORY(keyId, cert.keyId(), 8);
}

void test_Certificate_setIssuerId_string(void) {
    ndn::Certificate cert;

    ndn::Error err = cert.setIssuerId("self");
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_EQUAL(4, cert.issuerIdSize());
    TEST_ASSERT_EQUAL_MEMORY("self", cert.issuerId(), 4);
}

void test_Certificate_setVersion(void) {
    ndn::Certificate cert;

    cert.setVersion(12345);
    TEST_ASSERT_EQUAL(12345, cert.version());
}

void test_Certificate_setPublicKey(void) {
    ndn::Certificate cert;

    // Simulated DER-encoded public key (just dummy data)
    const uint8_t key[] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
                           0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a};
    ndn::Error err = cert.setPublicKey(key, sizeof(key));
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_EQUAL(sizeof(key), cert.publicKeySize());
    TEST_ASSERT_EQUAL_MEMORY(key, cert.publicKey(), sizeof(key));
}

void test_Certificate_setValidity(void) {
    ndn::Certificate cert;

    ndn::ValidityPeriod vp;
    vp.setNotBefore(2024, 1, 1, 0, 0, 0);
    vp.setNotAfter(2025, 12, 31, 23, 59, 59);

    cert.setValidity(vp);

    TEST_ASSERT_TRUE(cert.validity().equals(vp));
}

// =============================================================================
// Certificate tests - Name building
// =============================================================================

void test_Certificate_buildName(void) {
    ndn::Certificate cert;

    cert.setIdentityName("/example/user");

    const uint8_t keyId[] = {0xAB, 0xCD};
    cert.setKeyId(keyId, 2);

    cert.setIssuerId("self");
    cert.setVersion(1);

    ndn::Name name;
    ndn::Error err = cert.buildName(name);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    // Should be: /example/user/KEY/<keyId>/self/<version>
    TEST_ASSERT_EQUAL(6, name.componentCount());

    // Check "KEY" component
    auto comp = name.component(2);
    TEST_ASSERT_EQUAL(3, comp.size);
    TEST_ASSERT_EQUAL_MEMORY("KEY", comp.value, 3);
}

// =============================================================================
// Certificate tests - Signature
// =============================================================================

void test_Certificate_signWithDigestSha256(void) {
    ndn::Certificate cert;

    cert.setIdentityName("/test/cert");
    const uint8_t keyId[] = {0x01, 0x02, 0x03, 0x04};
    cert.setKeyId(keyId, 4);
    cert.setIssuerId("self");
    cert.setVersion(1);

    const uint8_t pubKey[] = {0x30, 0x59, 0x30, 0x13};
    cert.setPublicKey(pubKey, sizeof(pubKey));

    cert.validity().setNotBefore(2024, 1, 1, 0, 0, 0);
    cert.validity().setNotAfter(2025, 12, 31, 23, 59, 59);

    ndn::Error err = cert.signWithDigestSha256();
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_EQUAL(ndn::SignatureType::DigestSha256, cert.signatureType());
}

void test_Certificate_verifyDigestSha256_valid(void) {
    ndn::Certificate cert;

    cert.setIdentityName("/test/cert");
    const uint8_t keyId[] = {0x01, 0x02, 0x03, 0x04};
    cert.setKeyId(keyId, 4);
    cert.setIssuerId("self");
    cert.setVersion(1);

    const uint8_t pubKey[] = {0x30, 0x59, 0x30, 0x13};
    cert.setPublicKey(pubKey, sizeof(pubKey));

    cert.validity().setNotBefore(2024, 1, 1, 0, 0, 0);
    cert.validity().setNotAfter(2025, 12, 31, 23, 59, 59);

    TEST_ASSERT_EQUAL(ndn::Error::Success, cert.signWithDigestSha256());
    TEST_ASSERT_TRUE(cert.verifyDigestSha256());
}

void test_Certificate_verifyDigestSha256_after_modification_fails(void) {
    ndn::Certificate cert;

    cert.setIdentityName("/test/cert");
    const uint8_t keyId[] = {0x01, 0x02, 0x03, 0x04};
    cert.setKeyId(keyId, 4);
    cert.setIssuerId("self");
    cert.setVersion(1);

    const uint8_t pubKey[] = {0x30, 0x59, 0x30, 0x13};
    cert.setPublicKey(pubKey, sizeof(pubKey));

    cert.validity().setNotBefore(2024, 1, 1, 0, 0, 0);
    cert.validity().setNotAfter(2025, 12, 31, 23, 59, 59);

    TEST_ASSERT_EQUAL(ndn::Error::Success, cert.signWithDigestSha256());
    TEST_ASSERT_TRUE(cert.verifyDigestSha256());

    // Modify after signing
    cert.setVersion(2);

    // Verification should fail
    TEST_ASSERT_FALSE(cert.verifyDigestSha256());
}

void test_Certificate_signWithHmac(void) {
    ndn::Certificate cert;

    cert.setIdentityName("/test/hmac");
    const uint8_t keyId[] = {0x11, 0x22, 0x33, 0x44};
    cert.setKeyId(keyId, 4);
    cert.setIssuerId("issuer");
    cert.setVersion(100);

    const uint8_t pubKey[] = {0x04, 0x00, 0x01, 0x02};
    cert.setPublicKey(pubKey, sizeof(pubKey));

    cert.validity().setNotBefore(2024, 6, 1, 0, 0, 0);
    cert.validity().setNotAfter(2024, 12, 31, 23, 59, 59);

    const uint8_t hmacKey[] = "secret-key-for-hmac";
    ndn::Error err = cert.signWithHmac(hmacKey, sizeof(hmacKey) - 1);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_EQUAL(ndn::SignatureType::SignatureHmacWithSha256, cert.signatureType());
}

void test_Certificate_verifyHmac_valid(void) {
    ndn::Certificate cert;

    cert.setIdentityName("/test/hmac");
    const uint8_t keyId[] = {0x11, 0x22, 0x33, 0x44};
    cert.setKeyId(keyId, 4);
    cert.setIssuerId("issuer");
    cert.setVersion(100);

    const uint8_t pubKey[] = {0x04, 0x00, 0x01, 0x02};
    cert.setPublicKey(pubKey, sizeof(pubKey));

    cert.validity().setNotBefore(2024, 6, 1, 0, 0, 0);
    cert.validity().setNotAfter(2024, 12, 31, 23, 59, 59);

    const uint8_t hmacKey[] = "secret-key-for-hmac";
    TEST_ASSERT_EQUAL(ndn::Error::Success, cert.signWithHmac(hmacKey, sizeof(hmacKey) - 1));
    TEST_ASSERT_TRUE(cert.verifyHmac(hmacKey, sizeof(hmacKey) - 1));
}

void test_Certificate_verifyHmac_wrong_key_fails(void) {
    ndn::Certificate cert;

    cert.setIdentityName("/test/hmac");
    const uint8_t keyId[] = {0x11, 0x22, 0x33, 0x44};
    cert.setKeyId(keyId, 4);
    cert.setIssuerId("issuer");
    cert.setVersion(100);

    const uint8_t pubKey[] = {0x04, 0x00, 0x01, 0x02};
    cert.setPublicKey(pubKey, sizeof(pubKey));

    cert.validity().setNotBefore(2024, 6, 1, 0, 0, 0);
    cert.validity().setNotAfter(2024, 12, 31, 23, 59, 59);

    const uint8_t correctKey[] = "correct-key";
    const uint8_t wrongKey[] = "wrong-key!!";

    TEST_ASSERT_EQUAL(ndn::Error::Success, cert.signWithHmac(correctKey, sizeof(correctKey) - 1));

    TEST_ASSERT_TRUE(cert.verifyHmac(correctKey, sizeof(correctKey) - 1));
    TEST_ASSERT_FALSE(cert.verifyHmac(wrongKey, sizeof(wrongKey) - 1));
}

void test_Certificate_signWithHmac_null_key_fails(void) {
    ndn::Certificate cert;

    cert.setIdentityName("/test");
    cert.setIssuerId("self");

    ndn::Error err = cert.signWithHmac(nullptr, 0);
    TEST_ASSERT_EQUAL(ndn::Error::InvalidParam, err);
}

// =============================================================================
// Certificate tests - Validity check
// =============================================================================

void test_Certificate_isValidAt(void) {
    ndn::Certificate cert;

    cert.validity().setNotBefore(2024, 6, 1, 0, 0, 0);
    cert.validity().setNotAfter(2024, 12, 31, 23, 59, 59);

    TEST_ASSERT_TRUE(cert.isValidAt("20240701T120000"));
    TEST_ASSERT_FALSE(cert.isValidAt("20240101T000000"));
    TEST_ASSERT_FALSE(cert.isValidAt("20250101T000000"));
}

// =============================================================================
// Certificate tests - Encode/Decode
// =============================================================================

void test_Certificate_encode_decode_roundtrip(void) {
    ndn::Certificate original;

    original.setIdentityName("/ndn/test/user");
    const uint8_t keyId[] = {0xDE, 0xAD, 0xBE, 0xEF};
    original.setKeyId(keyId, 4);
    original.setIssuerId("self");
    original.setVersion(12345);

    const uint8_t pubKey[] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86};
    original.setPublicKey(pubKey, sizeof(pubKey));

    original.validity().setNotBefore(2024, 1, 1, 0, 0, 0);
    original.validity().setNotAfter(2025, 12, 31, 23, 59, 59);

    TEST_ASSERT_EQUAL(ndn::Error::Success, original.signWithDigestSha256());

    // Encode
    uint8_t buf[512];
    size_t len = 0;
    ndn::Error err = original.encode(buf, sizeof(buf), len);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_TRUE(len > 0);

    // Decode
    auto decoded = ndn::Certificate::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    // Compare fields
    TEST_ASSERT_EQUAL(original.keyIdSize(), decoded.value.keyIdSize());
    TEST_ASSERT_EQUAL_MEMORY(original.keyId(), decoded.value.keyId(), original.keyIdSize());

    TEST_ASSERT_EQUAL(original.issuerIdSize(), decoded.value.issuerIdSize());
    TEST_ASSERT_EQUAL_MEMORY(original.issuerId(), decoded.value.issuerId(),
                             original.issuerIdSize());

    TEST_ASSERT_EQUAL(original.publicKeySize(), decoded.value.publicKeySize());
    TEST_ASSERT_EQUAL_MEMORY(original.publicKey(), decoded.value.publicKey(),
                             original.publicKeySize());

    TEST_ASSERT_EQUAL(original.signatureType(), decoded.value.signatureType());
}

void test_Certificate_fromData(void) {
    // Create a Data packet that looks like a certificate
    ndn::Data data;

    // Build certificate name: /example/KEY/<keyId>/self/<version>
    ndn::Name certName;
    certName.appendComponent(reinterpret_cast<const uint8_t*>("example"), 7);
    certName.appendComponent(reinterpret_cast<const uint8_t*>("KEY"), 3);
    const uint8_t keyId[] = {0x01, 0x02};
    certName.appendComponent(keyId, 2);
    certName.appendComponent(reinterpret_cast<const uint8_t*>("self"), 4);
    const uint8_t version[] = {0x01};
    certName.appendComponent(version, 1);

    data.setName(certName);
    data.setContentType(ndn::ContentType::Key);

    const uint8_t pubKey[] = {0x30, 0x59};
    data.setContent(pubKey, sizeof(pubKey));
    data.signWithDigestSha256();

    // Convert to Certificate
    auto result = ndn::Certificate::fromData(data);
    TEST_ASSERT_TRUE(result.ok());

    TEST_ASSERT_EQUAL(1, result.value.identityName().componentCount());
    TEST_ASSERT_EQUAL(2, result.value.keyIdSize());
    TEST_ASSERT_EQUAL(4, result.value.issuerIdSize());
    TEST_ASSERT_EQUAL(2, result.value.publicKeySize());
}

void test_Certificate_fromData_wrong_content_type_fails(void) {
    ndn::Data data;
    data.setName("/test/KEY/123/self/1");
    data.setContentType(ndn::ContentType::Blob);  // Wrong type

    auto result = ndn::Certificate::fromData(data);
    TEST_ASSERT_FALSE(result.ok());
    TEST_ASSERT_EQUAL(ndn::Error::InvalidPacket, result.error);
}

void test_Certificate_fromData_no_key_component_fails(void) {
    ndn::Data data;
    data.setName("/test/without/key/component");
    data.setContentType(ndn::ContentType::Key);

    auto result = ndn::Certificate::fromData(data);
    TEST_ASSERT_FALSE(result.ok());
}

void test_Certificate_toData(void) {
    ndn::Certificate cert;

    cert.setIdentityName("/test/user");
    const uint8_t keyId[] = {0xAA, 0xBB};
    cert.setKeyId(keyId, 2);
    cert.setIssuerId("issuer");
    cert.setVersion(999);

    const uint8_t pubKey[] = {0x04, 0x01, 0x02, 0x03};
    cert.setPublicKey(pubKey, sizeof(pubKey));

    ndn::Data data;
    ndn::Error err = cert.toData(data);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_EQUAL(ndn::ContentType::Key, data.contentType());
    TEST_ASSERT_EQUAL(sizeof(pubKey), data.contentSize());
    TEST_ASSERT_EQUAL_MEMORY(pubKey, data.content(), sizeof(pubKey));
}

// =============================================================================
// Test runner
// =============================================================================

void run_certificate_tests(void) {
    // ValidityPeriod tests
    RUN_TEST(test_ValidityPeriod_setNotBefore_datetime);
    RUN_TEST(test_ValidityPeriod_setNotAfter_datetime);
    RUN_TEST(test_ValidityPeriod_setNotBefore_string);
    RUN_TEST(test_ValidityPeriod_setNotBefore_invalid_string);
    RUN_TEST(test_ValidityPeriod_fromStrings);
    RUN_TEST(test_ValidityPeriod_fromStrings_invalid);
    RUN_TEST(test_ValidityPeriod_isValidAt_within_range);
    RUN_TEST(test_ValidityPeriod_isValidAt_before_range);
    RUN_TEST(test_ValidityPeriod_isValidAt_after_range);
    RUN_TEST(test_ValidityPeriod_encode_decode_roundtrip);
    RUN_TEST(test_ValidityPeriod_equals);

    // Certificate basic tests
    RUN_TEST(test_Certificate_default_constructor);
    RUN_TEST(test_Certificate_setIdentityName);
    RUN_TEST(test_Certificate_setKeyId);
    RUN_TEST(test_Certificate_setIssuerId_string);
    RUN_TEST(test_Certificate_setVersion);
    RUN_TEST(test_Certificate_setPublicKey);
    RUN_TEST(test_Certificate_setValidity);

    // Certificate name building
    RUN_TEST(test_Certificate_buildName);

    // Certificate signature tests
    RUN_TEST(test_Certificate_signWithDigestSha256);
    RUN_TEST(test_Certificate_verifyDigestSha256_valid);
    RUN_TEST(test_Certificate_verifyDigestSha256_after_modification_fails);
    RUN_TEST(test_Certificate_signWithHmac);
    RUN_TEST(test_Certificate_verifyHmac_valid);
    RUN_TEST(test_Certificate_verifyHmac_wrong_key_fails);
    RUN_TEST(test_Certificate_signWithHmac_null_key_fails);

    // Certificate validity check
    RUN_TEST(test_Certificate_isValidAt);

    // Certificate encode/decode tests
    RUN_TEST(test_Certificate_encode_decode_roundtrip);
    RUN_TEST(test_Certificate_fromData);
    RUN_TEST(test_Certificate_fromData_wrong_content_type_fails);
    RUN_TEST(test_Certificate_fromData_no_key_component_fails);
    RUN_TEST(test_Certificate_toData);
}
