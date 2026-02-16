#include "ndn/interest.hpp"
#include <cstring>
#include "unity.h"

// =============================================================================
// Interest construction and setters
// =============================================================================

void test_Interest_default_construction(void) {
    ndn::Interest interest;

    TEST_ASSERT_TRUE(interest.name().empty());
    TEST_ASSERT_FALSE(interest.nonce().has_value());
    TEST_ASSERT_EQUAL(ndn::INTEREST_DEFAULT_LIFETIME_MS, interest.lifetime());
    TEST_ASSERT_FALSE(interest.hopLimit().has_value());
}

void test_Interest_construction_with_Name(void) {
    auto nameResult = ndn::Name::fromUri("/test/name");
    TEST_ASSERT_TRUE(nameResult.ok());

    ndn::Interest interest(nameResult.value);
    TEST_ASSERT_EQUAL(2, interest.name().componentCount());
}

void test_Interest_setName_with_Name_object(void) {
    auto nameResult = ndn::Name::fromUri("/sensor/data");
    TEST_ASSERT_TRUE(nameResult.ok());

    ndn::Interest interest;
    interest.setName(nameResult.value);

    TEST_ASSERT_EQUAL(2, interest.name().componentCount());
}

void test_Interest_setName_with_URI_string(void) {
    ndn::Interest interest;
    ndn::Error err = interest.setName("/sensor/temperature");

    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_EQUAL(2, interest.name().componentCount());
}

void test_Interest_setNonce_and_nonce_getter(void) {
    ndn::Interest interest;
    TEST_ASSERT_FALSE(interest.nonce().has_value());

    interest.setNonce(0x12345678);
    TEST_ASSERT_TRUE(interest.nonce().has_value());
    TEST_ASSERT_EQUAL(0x12345678, *interest.nonce());
}

void test_Interest_generateNonce_creates_a_value(void) {
    ndn::Interest interest;
    interest.generateNonce();

    TEST_ASSERT_TRUE(interest.nonce().has_value());
}

void test_Interest_setLifetime(void) {
    ndn::Interest interest;
    TEST_ASSERT_EQUAL(ndn::INTEREST_DEFAULT_LIFETIME_MS, interest.lifetime());

    interest.setLifetime(10000);
    TEST_ASSERT_EQUAL(10000, interest.lifetime());
}

void test_Interest_setHopLimit_and_decrementHopLimit(void) {
    ndn::Interest interest;
    TEST_ASSERT_FALSE(interest.hopLimit().has_value());

    interest.setHopLimit(10);
    TEST_ASSERT_TRUE(interest.hopLimit().has_value());
    TEST_ASSERT_EQUAL(10, *interest.hopLimit());

    interest.decrementHopLimit();
    TEST_ASSERT_EQUAL(9, *interest.hopLimit());

    // Reduce to 0
    for (int i = 0; i < 9; ++i) {
        interest.decrementHopLimit();
    }
    TEST_ASSERT_EQUAL(0, *interest.hopLimit());

    // Does not go below 0
    interest.decrementHopLimit();
    TEST_ASSERT_EQUAL(0, *interest.hopLimit());
}

void test_Interest_method_chaining(void) {
    auto nameResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(nameResult.ok());

    ndn::Interest interest;
    interest.setName(nameResult.value).setLifetime(5000).setNonce(123).setHopLimit(5);

    TEST_ASSERT_EQUAL(1, interest.name().componentCount());
    TEST_ASSERT_EQUAL(5000, interest.lifetime());
    TEST_ASSERT_EQUAL(123, *interest.nonce());
    TEST_ASSERT_EQUAL(5, *interest.hopLimit());
}

// =============================================================================
// Interest encode/decode
// =============================================================================

void test_Interest_encode_produces_valid_TLV(void) {
    ndn::Interest interest;
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.setName("/test"));
    interest.setNonce(0x12345678);

    uint8_t buf[128];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.encode(buf, sizeof(buf), len));

    // Interest TLV type = 0x05
    TEST_ASSERT_EQUAL(0x05, buf[0]);
    TEST_ASSERT_TRUE(len > 0);
}

void test_Interest_encode_decode_roundtrip_basic(void) {
    ndn::Interest original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/sensor/temperature"));
    original.setNonce(0xAABBCCDD);

    // Encode
    uint8_t buf[128];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    // Decode
    auto decoded = ndn::Interest::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    // Verify
    TEST_ASSERT_TRUE(original.name().equals(decoded.value.name()));
    TEST_ASSERT_TRUE(decoded.value.nonce().has_value());
    TEST_ASSERT_EQUAL(0xAABBCCDD, *decoded.value.nonce());
}

void test_Interest_encode_decode_roundtrip_with_lifetime(void) {
    ndn::Interest original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test"));
    original.setLifetime(8000);  // non-default
    original.generateNonce();

    uint8_t buf[128];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Interest::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    TEST_ASSERT_EQUAL(8000, decoded.value.lifetime());
}

void test_Interest_encode_decode_roundtrip_with_hop_limit(void) {
    ndn::Interest original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test"));
    original.setHopLimit(64);
    original.generateNonce();

    uint8_t buf[128];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Interest::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    TEST_ASSERT_TRUE(decoded.value.hopLimit().has_value());
    TEST_ASSERT_EQUAL(64, *decoded.value.hopLimit());
}

void test_Interest_encode_decode_roundtrip_with_all_fields(void) {
    ndn::Interest original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/a/b/c"));
    original.setNonce(0x11223344);
    original.setLifetime(6000);
    original.setHopLimit(32);

    uint8_t buf[ndn::PACKET_MAX_SIZE];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Interest::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());

    TEST_ASSERT_TRUE(original.name().equals(decoded.value.name()));
    TEST_ASSERT_EQUAL(0x11223344, *decoded.value.nonce());
    TEST_ASSERT_EQUAL(6000, decoded.value.lifetime());
    TEST_ASSERT_EQUAL(32, *decoded.value.hopLimit());
}

void test_Interest_decode_fails_on_invalid_type(void) {
    // Parse Data packet (0x06) as Interest
    const uint8_t data[] = {0x06, 0x04, 0x07, 0x02, 0x08, 0x00};
    auto result = ndn::Interest::fromWire(data, sizeof(data));

    TEST_ASSERT_FALSE(result.ok());
    TEST_ASSERT_EQUAL(ndn::Error::InvalidPacket, result.error);
}

void test_Interest_decode_fails_without_Name(void) {
    // Invalid Interest without Name
    const uint8_t data[] = {0x05, 0x06, 0x0a, 0x04, 0x00, 0x00, 0x00, 0x00};
    auto result = ndn::Interest::fromWire(data, sizeof(data));

    TEST_ASSERT_FALSE(result.ok());
    TEST_ASSERT_EQUAL(ndn::Error::InvalidPacket, result.error);
}

void test_Interest_encode_fails_on_buffer_too_small(void) {
    ndn::Interest interest;
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.setName("/very/long/name/path"));
    interest.generateNonce();

    uint8_t buf[5];  // Too small
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::BufferTooSmall, interest.encode(buf, sizeof(buf), len));
}

// =============================================================================
// MustBeFresh tests
// =============================================================================

void test_Interest_mustBeFresh_default_is_false(void) {
    ndn::Interest interest;
    TEST_ASSERT_FALSE(interest.mustBeFresh());
}

void test_Interest_setMustBeFresh(void) {
    ndn::Interest interest;
    interest.setMustBeFresh(true);
    TEST_ASSERT_TRUE(interest.mustBeFresh());

    interest.setMustBeFresh(false);
    TEST_ASSERT_FALSE(interest.mustBeFresh());
}

void test_Interest_encode_decode_roundtrip_with_mustBeFresh(void) {
    ndn::Interest original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/fresh"));
    original.setMustBeFresh(true);
    original.generateNonce();

    uint8_t buf[128];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Interest::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());
    TEST_ASSERT_TRUE(decoded.value.mustBeFresh());
}

void test_Interest_encode_decode_roundtrip_without_mustBeFresh(void) {
    ndn::Interest original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/stale"));
    original.setMustBeFresh(false);
    original.generateNonce();

    uint8_t buf[128];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Interest::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());
    TEST_ASSERT_FALSE(decoded.value.mustBeFresh());
}

void test_Interest_encode_decode_roundtrip_with_canBePrefix_and_mustBeFresh(void) {
    ndn::Interest original;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.setName("/test/both"));
    original.setCanBePrefix(true);
    original.setMustBeFresh(true);
    original.generateNonce();

    uint8_t buf[128];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.encode(buf, sizeof(buf), len));

    auto decoded = ndn::Interest::fromWire(buf, len);
    TEST_ASSERT_TRUE(decoded.ok());
    TEST_ASSERT_TRUE(decoded.value.canBePrefix());
    TEST_ASSERT_TRUE(decoded.value.mustBeFresh());
}

// =============================================================================
// Test runner
// =============================================================================

void run_interest_tests(void) {
    RUN_TEST(test_Interest_default_construction);
    RUN_TEST(test_Interest_construction_with_Name);
    RUN_TEST(test_Interest_setName_with_Name_object);
    RUN_TEST(test_Interest_setName_with_URI_string);
    RUN_TEST(test_Interest_setNonce_and_nonce_getter);
    RUN_TEST(test_Interest_generateNonce_creates_a_value);
    RUN_TEST(test_Interest_setLifetime);
    RUN_TEST(test_Interest_setHopLimit_and_decrementHopLimit);
    RUN_TEST(test_Interest_method_chaining);
    RUN_TEST(test_Interest_encode_produces_valid_TLV);
    RUN_TEST(test_Interest_encode_decode_roundtrip_basic);
    RUN_TEST(test_Interest_encode_decode_roundtrip_with_lifetime);
    RUN_TEST(test_Interest_encode_decode_roundtrip_with_hop_limit);
    RUN_TEST(test_Interest_encode_decode_roundtrip_with_all_fields);
    RUN_TEST(test_Interest_decode_fails_on_invalid_type);
    RUN_TEST(test_Interest_decode_fails_without_Name);
    RUN_TEST(test_Interest_encode_fails_on_buffer_too_small);
    RUN_TEST(test_Interest_mustBeFresh_default_is_false);
    RUN_TEST(test_Interest_setMustBeFresh);
    RUN_TEST(test_Interest_encode_decode_roundtrip_with_mustBeFresh);
    RUN_TEST(test_Interest_encode_decode_roundtrip_without_mustBeFresh);
    RUN_TEST(test_Interest_encode_decode_roundtrip_with_canBePrefix_and_mustBeFresh);
}
