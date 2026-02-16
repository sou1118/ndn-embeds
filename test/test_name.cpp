#include "ndn/name.hpp"
#include <cstring>
#include "unity.h"

// =============================================================================
// Name::fromUri
// =============================================================================

void test_Name_fromUri_parses_simple_path(void) {
    auto result = ndn::Name::fromUri("/test/hello/world");
    TEST_ASSERT_TRUE(result.ok());
    TEST_ASSERT_EQUAL(3, result.value.componentCount());

    auto c0 = result.value.component(0);
    TEST_ASSERT_EQUAL(4, c0.size);
    TEST_ASSERT_EQUAL_STRING_LEN("test", c0.value, 4);

    auto c1 = result.value.component(1);
    TEST_ASSERT_EQUAL(5, c1.size);
    TEST_ASSERT_EQUAL_STRING_LEN("hello", c1.value, 5);

    auto c2 = result.value.component(2);
    TEST_ASSERT_EQUAL(5, c2.size);
    TEST_ASSERT_EQUAL_STRING_LEN("world", c2.value, 5);
}

void test_Name_fromUri_parses_with_ndn_prefix(void) {
    auto result = ndn::Name::fromUri("ndn:/test/path");
    TEST_ASSERT_TRUE(result.ok());
    TEST_ASSERT_EQUAL(2, result.value.componentCount());
}

void test_Name_fromUri_handles_empty_name(void) {
    auto r1 = ndn::Name::fromUri("/");
    TEST_ASSERT_TRUE(r1.ok());
    TEST_ASSERT_EQUAL(0, r1.value.componentCount());
    TEST_ASSERT_TRUE(r1.value.empty());

    auto r2 = ndn::Name::fromUri("");
    TEST_ASSERT_TRUE(r2.ok());
    TEST_ASSERT_EQUAL(0, r2.value.componentCount());
}

void test_Name_fromUri_decodes_percent_encoded_chars(void) {
    auto result = ndn::Name::fromUri("/hello%20world");
    TEST_ASSERT_TRUE(result.ok());
    TEST_ASSERT_EQUAL(1, result.value.componentCount());

    auto c0 = result.value.component(0);
    TEST_ASSERT_EQUAL(11, c0.size);  // "hello world"
    TEST_ASSERT_EQUAL_STRING_LEN("hello world", c0.value, 11);
}

void test_Name_fromUri_handles_single_component(void) {
    auto result = ndn::Name::fromUri("/sensor");
    TEST_ASSERT_TRUE(result.ok());
    TEST_ASSERT_EQUAL(1, result.value.componentCount());
}

// =============================================================================
// Name::toUri
// =============================================================================

void test_Name_toUri_produces_correct_output(void) {
    auto result = ndn::Name::fromUri("/test/hello");
    TEST_ASSERT_TRUE(result.ok());

    char buf[64];
    size_t len = result.value.toUri(buf, sizeof(buf));

    TEST_ASSERT_EQUAL_STRING("/test/hello", buf);
    TEST_ASSERT_EQUAL(11, len);
}

void test_Name_toUri_handles_empty_name(void) {
    ndn::Name name;
    char buf[16];
    size_t len = name.toUri(buf, sizeof(buf));

    TEST_ASSERT_EQUAL_STRING("/", buf);
    TEST_ASSERT_EQUAL(1, len);
}

void test_Name_toUri_percent_encodes_special_chars(void) {
    ndn::Name name;
    const uint8_t binData[] = {0x00, 0xFF};
    TEST_ASSERT_EQUAL(ndn::Error::Success, name.appendComponent(binData, 2));

    char buf[32];
    name.toUri(buf, sizeof(buf));

    // Binary data should be percent-encoded
    TEST_ASSERT_TRUE(strstr(buf, "%00") != nullptr);
    TEST_ASSERT_TRUE(strstr(buf, "%FF") != nullptr);
}

// =============================================================================
// Name::appendComponent
// =============================================================================

void test_Name_appendComponent_adds_components(void) {
    ndn::Name name;
    TEST_ASSERT_EQUAL(0, name.componentCount());

    TEST_ASSERT_EQUAL(ndn::Error::Success, name.appendComponent("first"));
    TEST_ASSERT_EQUAL(1, name.componentCount());

    TEST_ASSERT_EQUAL(ndn::Error::Success, name.appendComponent("second"));
    TEST_ASSERT_EQUAL(2, name.componentCount());

    auto c0 = name.component(0);
    TEST_ASSERT_EQUAL_STRING_LEN("first", c0.value, 5);

    auto c1 = name.component(1);
    TEST_ASSERT_EQUAL_STRING_LEN("second", c1.value, 6);
}

void test_Name_appendComponent_fails_when_too_many_components(void) {
    ndn::Name name;

    // Add NAME_MAX_COMPONENTS (10) components
    for (size_t i = 0; i < ndn::NAME_MAX_COMPONENTS; ++i) {
        TEST_ASSERT_EQUAL(ndn::Error::Success, name.appendComponent("x"));
    }

    // 11th one should fail
    TEST_ASSERT_EQUAL(ndn::Error::TooManyComponents, name.appendComponent("overflow"));
}

// =============================================================================
// Name::encode / fromWire
// =============================================================================

void test_Name_encode_decode_roundtrip(void) {
    auto original = ndn::Name::fromUri("/sensor/temperature/room1");
    TEST_ASSERT_TRUE(original.ok());

    // Encode
    uint8_t buf[128];
    size_t encodedLen = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, original.value.encode(buf, sizeof(buf), encodedLen));
    TEST_ASSERT_TRUE(encodedLen > 0);

    // Decode
    auto decoded = ndn::Name::fromWire(buf, encodedLen);
    TEST_ASSERT_TRUE(decoded.ok());

    // Compare
    TEST_ASSERT_TRUE(original.value.equals(decoded.value));
    TEST_ASSERT_EQUAL(original.value.componentCount(), decoded.value.componentCount());

    // Verify each component
    for (size_t i = 0; i < original.value.componentCount(); ++i) {
        auto origComp = original.value.component(i);
        auto decComp = decoded.value.component(i);
        TEST_ASSERT_EQUAL(origComp.size, decComp.size);
        TEST_ASSERT_EQUAL_MEMORY(origComp.value, decComp.value, origComp.size);
    }
}

void test_Name_encode_produces_correct_TLV(void) {
    auto result = ndn::Name::fromUri("/a/b");
    TEST_ASSERT_TRUE(result.ok());

    uint8_t buf[64];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, result.value.encode(buf, sizeof(buf), len));

    // Name TLV: type=0x07
    TEST_ASSERT_EQUAL(0x07, buf[0]);

    // Should contain two GenericNameComponent (0x08) inside
    // Structure: 07 LL [08 01 'a'] [08 01 'b']
    //       07 06 08 01 61 08 01 62
    TEST_ASSERT_EQUAL(8, len);
    TEST_ASSERT_EQUAL(0x08, buf[2]);  // First component type
    TEST_ASSERT_EQUAL(1, buf[3]);     // Length
    TEST_ASSERT_EQUAL('a', buf[4]);
    TEST_ASSERT_EQUAL(0x08, buf[5]);  // Second component type
    TEST_ASSERT_EQUAL(1, buf[6]);
    TEST_ASSERT_EQUAL('b', buf[7]);
}

// =============================================================================
// Name::compare / equals / isPrefixOf
// =============================================================================

void test_Name_equals_works_correctly(void) {
    auto n1 = ndn::Name::fromUri("/a/b/c");
    auto n2 = ndn::Name::fromUri("/a/b/c");
    auto n3 = ndn::Name::fromUri("/a/b");

    TEST_ASSERT_TRUE(n1.ok());
    TEST_ASSERT_TRUE(n2.ok());
    TEST_ASSERT_TRUE(n3.ok());

    TEST_ASSERT_TRUE(n1.value.equals(n2.value));
    TEST_ASSERT_TRUE(n1.value == n2.value);
    TEST_ASSERT_FALSE(n1.value.equals(n3.value));
    TEST_ASSERT_TRUE(n1.value != n3.value);
}

void test_Name_compare_orders_correctly(void) {
    auto a = ndn::Name::fromUri("/a");
    auto ab = ndn::Name::fromUri("/a/b");
    auto b = ndn::Name::fromUri("/b");

    TEST_ASSERT_TRUE(a.ok());
    TEST_ASSERT_TRUE(ab.ok());
    TEST_ASSERT_TRUE(b.ok());

    // /a < /a/b (prefix comes first)
    TEST_ASSERT_TRUE(a.value.compare(ab.value) < 0);

    // /a < /b (lexicographic)
    TEST_ASSERT_TRUE(a.value.compare(b.value) < 0);

    // /a/b < /b
    TEST_ASSERT_TRUE(ab.value.compare(b.value) < 0);

    // Same name returns 0
    TEST_ASSERT_EQUAL(0, a.value.compare(a.value));
}

void test_Name_isPrefixOf_works_correctly(void) {
    auto prefix = ndn::Name::fromUri("/a/b");
    auto full = ndn::Name::fromUri("/a/b/c/d");
    auto other = ndn::Name::fromUri("/x/y");
    auto exact = ndn::Name::fromUri("/a/b");

    TEST_ASSERT_TRUE(prefix.ok());
    TEST_ASSERT_TRUE(full.ok());
    TEST_ASSERT_TRUE(other.ok());
    TEST_ASSERT_TRUE(exact.ok());

    TEST_ASSERT_TRUE(prefix.value.isPrefixOf(full.value));
    TEST_ASSERT_TRUE(prefix.value.isPrefixOf(exact.value));  // Self is also prefix
    TEST_ASSERT_FALSE(prefix.value.isPrefixOf(other.value));
    TEST_ASSERT_FALSE(full.value.isPrefixOf(prefix.value));  // Reverse is not
}

// =============================================================================
// Name::hash
// =============================================================================

void test_Name_hash_is_consistent(void) {
    auto n1 = ndn::Name::fromUri("/test/name");
    auto n2 = ndn::Name::fromUri("/test/name");
    auto n3 = ndn::Name::fromUri("/different/name");

    TEST_ASSERT_TRUE(n1.ok());
    TEST_ASSERT_TRUE(n2.ok());
    TEST_ASSERT_TRUE(n3.ok());

    // Same name produces same hash
    TEST_ASSERT_EQUAL(n1.value.hash(), n2.value.hash());

    // Different names produce different hashes (collisions possible but unlikely here)
    TEST_ASSERT_NOT_EQUAL(n1.value.hash(), n3.value.hash());
}

// =============================================================================
// Test runner
// =============================================================================

void run_name_tests(void) {
    RUN_TEST(test_Name_fromUri_parses_simple_path);
    RUN_TEST(test_Name_fromUri_parses_with_ndn_prefix);
    RUN_TEST(test_Name_fromUri_handles_empty_name);
    RUN_TEST(test_Name_fromUri_decodes_percent_encoded_chars);
    RUN_TEST(test_Name_fromUri_handles_single_component);
    RUN_TEST(test_Name_toUri_produces_correct_output);
    RUN_TEST(test_Name_toUri_handles_empty_name);
    RUN_TEST(test_Name_toUri_percent_encodes_special_chars);
    RUN_TEST(test_Name_appendComponent_adds_components);
    RUN_TEST(test_Name_appendComponent_fails_when_too_many_components);
    RUN_TEST(test_Name_encode_decode_roundtrip);
    RUN_TEST(test_Name_encode_produces_correct_TLV);
    RUN_TEST(test_Name_equals_works_correctly);
    RUN_TEST(test_Name_compare_orders_correctly);
    RUN_TEST(test_Name_isPrefixOf_works_correctly);
    RUN_TEST(test_Name_hash_is_consistent);
}
