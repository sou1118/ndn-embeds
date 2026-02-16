#include "ndn/data.hpp"
#include <cstring>
#include "unity.h"

// =============================================================================
// Data construction and setters
// =============================================================================

void test_Data_default_construction(void) {
    ndn::Data data;

    TEST_ASSERT_TRUE(data.name().empty());
    TEST_ASSERT_FALSE(data.hasContent());
    TEST_ASSERT_EQUAL(0, data.contentSize());
    TEST_ASSERT_FALSE(data.freshnessPeriod().has_value());
}

void test_Data_construction_with_Name(void) {
    auto nameResult = ndn::Name::fromUri("/test/name");
    TEST_ASSERT_TRUE(nameResult.ok());

    ndn::Data data(nameResult.value);
    TEST_ASSERT_EQUAL(2, data.name().componentCount());
}

void test_Data_setName_with_Name_object(void) {
    auto nameResult = ndn::Name::fromUri("/sensor/data");
    TEST_ASSERT_TRUE(nameResult.ok());

    ndn::Data data;
    data.setName(nameResult.value);

    TEST_ASSERT_EQUAL(2, data.name().componentCount());
}

void test_Data_setName_with_URI_string(void) {
    ndn::Data data;
    ndn::Error err = data.setName("/sensor/temperature");

    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_EQUAL(2, data.name().componentCount());
}

void test_Data_setContent_with_string(void) {
    ndn::Data data;
    TEST_ASSERT_FALSE(data.hasContent());

    ndn::Error err = data.setContent("Hello, NDN!");
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_TRUE(data.hasContent());
    TEST_ASSERT_EQUAL(11, data.contentSize());
    TEST_ASSERT_EQUAL_STRING_LEN("Hello, NDN!", data.content(), 11);
}

void test_Data_setContent_with_binary_data(void) {
    ndn::Data data;
    const uint8_t binData[] = {0x01, 0x02, 0x03, 0x04, 0x05};

    ndn::Error err = data.setContent(binData, sizeof(binData));
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_TRUE(data.hasContent());
    TEST_ASSERT_EQUAL(5, data.contentSize());
    TEST_ASSERT_EQUAL_MEMORY(binData, data.content(), 5);
}

void test_Data_setContent_fails_when_too_large(void) {
    ndn::Data data;
    uint8_t largeData[ndn::DATA_MAX_CONTENT_SIZE + 1];
    memset(largeData, 0x42, sizeof(largeData));

    ndn::Error err = data.setContent(largeData, sizeof(largeData));
    TEST_ASSERT_EQUAL(ndn::Error::BufferTooSmall, err);
}

void test_Data_setFreshnessPeriod(void) {
    ndn::Data data;
    TEST_ASSERT_FALSE(data.freshnessPeriod().has_value());

    data.setFreshnessPeriod(10000);
    TEST_ASSERT_TRUE(data.freshnessPeriod().has_value());
    TEST_ASSERT_EQUAL(10000, *data.freshnessPeriod());
}

// =============================================================================
// Data encode/decode
// =============================================================================

void test_Data_encode_produces_valid_TLV(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("content"));

    uint8_t buf[128];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.encode(buf, sizeof(buf), len));

    // Data TLV type = 0x06
    TEST_ASSERT_EQUAL(0x06, buf[0]);
    TEST_ASSERT_TRUE(len > 0);
}

void test_Data_encode_decode_roundtrip_basic(void) {
    ndn::Data original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/sensor/temperature"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setContent("25.5 C"));

    // Encode
    uint8_t buf[128];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    // Decode
    auto decoded = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    // Verify
    TEST_ASSERT_TRUE(original.name().equals(decoded.value.name()));
    TEST_ASSERT_TRUE(decoded.value.hasContent());
    TEST_ASSERT_EQUAL(6, decoded.value.contentSize());
    TEST_ASSERT_EQUAL_STRING_LEN("25.5 C", decoded.value.content(), 6);
}

void test_Data_encode_decode_roundtrip_with_freshness(void) {
    ndn::Data original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setContent("data"));
    original.setFreshnessPeriod(5000);

    uint8_t buf[128];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    TEST_ASSERT_TRUE(decoded.value.freshnessPeriod().has_value());
    TEST_ASSERT_EQUAL(5000, *decoded.value.freshnessPeriod());
}

void test_Data_encode_decode_roundtrip_with_binary_content(void) {
    ndn::Data original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/binary/data"));

    const uint8_t binContent[] = {0x00, 0x01, 0xFF, 0xFE, 0x80};
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setContent(binContent, sizeof(binContent)));

    uint8_t buf[128];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    TEST_ASSERT_EQUAL(sizeof(binContent), decoded.value.contentSize());
    TEST_ASSERT_EQUAL_MEMORY(binContent, decoded.value.content(), sizeof(binContent));
}

void test_Data_encode_decode_roundtrip_without_content(void) {
    ndn::Data original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/empty/data"));
    // Do not set Content

    uint8_t buf[128];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    TEST_ASSERT_FALSE(decoded.value.hasContent());
    TEST_ASSERT_EQUAL(0, decoded.value.contentSize());
}

void test_Data_encode_decode_roundtrip_with_all_fields(void) {
    ndn::Data original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/a/b/c"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setContent("test content"));
    original.setFreshnessPeriod(30000);

    uint8_t buf[ndn::PACKET_MAX_SIZE];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    TEST_ASSERT_TRUE(original.name().equals(decoded.value.name()));
    TEST_ASSERT_EQUAL(original.contentSize(), decoded.value.contentSize());
    TEST_ASSERT_EQUAL_MEMORY(original.content(), decoded.value.content(), original.contentSize());
    TEST_ASSERT_EQUAL(30000, *decoded.value.freshnessPeriod());
}

void test_Data_decode_fails_on_invalid_type(void) {
    // Parse Interest packet (0x05) as Data
    const uint8_t interest[] = {0x05, 0x04, 0x07, 0x02, 0x08, 0x00};
    auto result = ndn::Data::fromWire(interest, sizeof(interest));

    TEST_ASSERT_FALSE(result.ok());
    TEST_ASSERT_EQUAL(ndn::Error::InvalidPacket, result.error);
}

void test_Data_decode_fails_without_Name(void) {
    // Invalid Data without Name
    const uint8_t data[] = {0x06, 0x04, 0x15, 0x02, 0x41, 0x42};  // Content only
    auto result = ndn::Data::fromWire(data, sizeof(data));

    TEST_ASSERT_FALSE(result.ok());
    TEST_ASSERT_EQUAL(ndn::Error::InvalidPacket, result.error);
}

void test_Data_encode_fails_on_buffer_too_small(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/test/data"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("some content here"));

    uint8_t buf[5];  // Too small
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::BufferTooSmall, data.encode(buf, sizeof(buf), len));
}

// =============================================================================
// Data content edge cases
// =============================================================================

void test_Data_handles_maximum_content_size(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setName("/max"));

    uint8_t maxContent[ndn::DATA_MAX_CONTENT_SIZE];
    memset(maxContent, 0xAB, sizeof(maxContent));

    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent(maxContent, sizeof(maxContent)));
    TEST_ASSERT_EQUAL(ndn::DATA_MAX_CONTENT_SIZE, data.contentSize());
}

void test_Data_content_can_be_replaced(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("first"));
    TEST_ASSERT_EQUAL(5, data.contentSize());

    TEST_ASSERT_EQUAL(ndn::Error::Success, data.setContent("second content"));
    TEST_ASSERT_EQUAL(14, data.contentSize());
    TEST_ASSERT_EQUAL_STRING_LEN("second content", data.content(), 14);
}

// =============================================================================
// FinalBlockId tests
// =============================================================================

void test_Data_finalBlockId_default_is_not_set(void) {
    ndn::Data data;
    TEST_ASSERT_FALSE(data.hasFinalBlockId());
    TEST_ASSERT_FALSE(data.finalBlockId().has_value());
}

void test_Data_setFinalBlockId(void) {
    ndn::Data data;
    data.setFinalBlockId(10);
    TEST_ASSERT_TRUE(data.hasFinalBlockId());
    TEST_ASSERT_EQUAL(10, *data.finalBlockId());
}

void test_Data_clearFinalBlockId(void) {
    ndn::Data data;
    data.setFinalBlockId(5);
    TEST_ASSERT_TRUE(data.hasFinalBlockId());

    data.clearFinalBlockId();
    TEST_ASSERT_FALSE(data.hasFinalBlockId());
}

void test_Data_encode_decode_roundtrip_with_finalBlockId(void) {
    ndn::Data original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/segment"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setContent("segment data"));
    original.setFinalBlockId(99);

    uint8_t buf[256];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());
    TEST_ASSERT_TRUE(decoded.value.hasFinalBlockId());
    TEST_ASSERT_EQUAL(99, *decoded.value.finalBlockId());
}

void test_Data_encode_decode_roundtrip_with_finalBlockId_zero(void) {
    ndn::Data original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/single"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setContent("only segment"));
    original.setFinalBlockId(0);

    uint8_t buf[256];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());
    TEST_ASSERT_TRUE(decoded.value.hasFinalBlockId());
    TEST_ASSERT_EQUAL(0, *decoded.value.finalBlockId());
}

void test_Data_encode_decode_roundtrip_with_finalBlockId_large(void) {
    ndn::Data original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/large"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setContent("data"));
    original.setFinalBlockId(0xFFFFFFFF);  // Large value

    uint8_t buf[256];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());
    TEST_ASSERT_TRUE(decoded.value.hasFinalBlockId());
    TEST_ASSERT_EQUAL(0xFFFFFFFF, *decoded.value.finalBlockId());
}

void test_Data_encode_decode_roundtrip_with_all_metainfo_fields(void) {
    ndn::Data original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/all"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setContent("content"));
    original.setContentType(ndn::ContentType::Blob);
    original.setFreshnessPeriod(5000);
    original.setFinalBlockId(42);

    uint8_t buf[256];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());
    TEST_ASSERT_EQUAL(ndn::ContentType::Blob, decoded.value.contentType());
    TEST_ASSERT_TRUE(decoded.value.freshnessPeriod().has_value());
    TEST_ASSERT_EQUAL(5000, *decoded.value.freshnessPeriod());
    TEST_ASSERT_TRUE(decoded.value.hasFinalBlockId());
    TEST_ASSERT_EQUAL(42, *decoded.value.finalBlockId());
}

// =============================================================================
// KeyLocator tests
// =============================================================================

void test_Data_keyLocator_default_is_not_set(void) {
    ndn::Data data;
    TEST_ASSERT_FALSE(data.hasKeyLocator());
    TEST_ASSERT_NULL(data.keyLocator());
}

void test_Data_setKeyLocator(void) {
    ndn::Data data;
    auto keyNameResult = ndn::Name::fromUri("/key/name");
    TEST_ASSERT_TRUE(keyNameResult.ok());

    data.setKeyLocator(keyNameResult.value);
    TEST_ASSERT_TRUE(data.hasKeyLocator());
    TEST_ASSERT_NOT_NULL(data.keyLocator());
    TEST_ASSERT_TRUE(data.keyLocator()->equals(keyNameResult.value));
}

void test_Data_clearKeyLocator(void) {
    ndn::Data data;
    auto keyNameResult = ndn::Name::fromUri("/key/name");
    TEST_ASSERT_TRUE(keyNameResult.ok());

    data.setKeyLocator(keyNameResult.value);
    TEST_ASSERT_TRUE(data.hasKeyLocator());

    data.clearKeyLocator();
    TEST_ASSERT_FALSE(data.hasKeyLocator());
    TEST_ASSERT_NULL(data.keyLocator());
}

void test_Data_encode_decode_roundtrip_with_keyLocator(void) {
    ndn::Data original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/data"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setContent("content"));

    auto keyNameResult = ndn::Name::fromUri("/key/rsa-001");
    TEST_ASSERT_TRUE(keyNameResult.ok());
    original.setKeyLocator(keyNameResult.value);

    uint8_t buf[512];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());
    TEST_ASSERT_TRUE(decoded.value.hasKeyLocator());
    TEST_ASSERT_NOT_NULL(decoded.value.keyLocator());
    TEST_ASSERT_TRUE(decoded.value.keyLocator()->equals(keyNameResult.value));
}

void test_Data_encode_decode_roundtrip_with_keyLocator_and_hmac(void) {
    ndn::Data original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/signed"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setContent("signed content"));

    auto keyNameResult = ndn::Name::fromUri("/hmac/key-001");
    TEST_ASSERT_TRUE(keyNameResult.ok());
    original.setKeyLocator(keyNameResult.value);

    // HMAC signature
    const uint8_t hmacKey[] = "test-hmac-key-1234567890123456";
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.signWithHmac(hmacKey, sizeof(hmacKey) - 1));

    uint8_t buf[512];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());
    TEST_ASSERT_TRUE(decoded.value.hasKeyLocator());
    TEST_ASSERT_TRUE(decoded.value.keyLocator()->equals(keyNameResult.value));
    TEST_ASSERT_EQUAL(ndn::SignatureType::SignatureHmacWithSha256, decoded.value.signatureType());
    TEST_ASSERT_TRUE(decoded.value.verifyHmac(hmacKey, sizeof(hmacKey) - 1));
}

void test_Data_encode_decode_roundtrip_with_all_signature_fields(void) {
    ndn::Data original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/all-sig"));
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setContent("full data"));
    original.setFreshnessPeriod(10000);
    original.setFinalBlockId(5);

    auto keyNameResult = ndn::Name::fromUri("/key/full-test");
    TEST_ASSERT_TRUE(keyNameResult.ok());
    original.setKeyLocator(keyNameResult.value);

    uint8_t buf[512];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    // Verify all fields
    TEST_ASSERT_TRUE(original.name().equals(decoded.value.name()));
    TEST_ASSERT_EQUAL(original.contentSize(), decoded.value.contentSize());
    TEST_ASSERT_EQUAL(10000, *decoded.value.freshnessPeriod());
    TEST_ASSERT_EQUAL(5, *decoded.value.finalBlockId());
    TEST_ASSERT_TRUE(decoded.value.hasKeyLocator());
    TEST_ASSERT_TRUE(decoded.value.keyLocator()->equals(keyNameResult.value));
}

// =============================================================================
// Test runner
// =============================================================================

void run_data_tests(void) {
    RUN_TEST(test_Data_default_construction);
    RUN_TEST(test_Data_construction_with_Name);
    RUN_TEST(test_Data_setName_with_Name_object);
    RUN_TEST(test_Data_setName_with_URI_string);
    RUN_TEST(test_Data_setContent_with_string);
    RUN_TEST(test_Data_setContent_with_binary_data);
    RUN_TEST(test_Data_setContent_fails_when_too_large);
    RUN_TEST(test_Data_setFreshnessPeriod);
    RUN_TEST(test_Data_encode_produces_valid_TLV);
    RUN_TEST(test_Data_encode_decode_roundtrip_basic);
    RUN_TEST(test_Data_encode_decode_roundtrip_with_freshness);
    RUN_TEST(test_Data_encode_decode_roundtrip_with_binary_content);
    RUN_TEST(test_Data_encode_decode_roundtrip_without_content);
    RUN_TEST(test_Data_encode_decode_roundtrip_with_all_fields);
    RUN_TEST(test_Data_decode_fails_on_invalid_type);
    RUN_TEST(test_Data_decode_fails_without_Name);
    RUN_TEST(test_Data_encode_fails_on_buffer_too_small);
    RUN_TEST(test_Data_handles_maximum_content_size);
    RUN_TEST(test_Data_content_can_be_replaced);
    RUN_TEST(test_Data_finalBlockId_default_is_not_set);
    RUN_TEST(test_Data_setFinalBlockId);
    RUN_TEST(test_Data_clearFinalBlockId);
    RUN_TEST(test_Data_encode_decode_roundtrip_with_finalBlockId);
    RUN_TEST(test_Data_encode_decode_roundtrip_with_finalBlockId_zero);
    RUN_TEST(test_Data_encode_decode_roundtrip_with_finalBlockId_large);
    RUN_TEST(test_Data_encode_decode_roundtrip_with_all_metainfo_fields);
    RUN_TEST(test_Data_keyLocator_default_is_not_set);
    RUN_TEST(test_Data_setKeyLocator);
    RUN_TEST(test_Data_clearKeyLocator);
    RUN_TEST(test_Data_encode_decode_roundtrip_with_keyLocator);
    RUN_TEST(test_Data_encode_decode_roundtrip_with_keyLocator_and_hmac);
    RUN_TEST(test_Data_encode_decode_roundtrip_with_all_signature_fields);
}
