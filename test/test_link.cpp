/**
 * @file test_link.cpp
 * @brief Link Object unit tests
 */

#include "ndn/link.hpp"

#include "ndn/data.hpp"
#include "ndn/interest.hpp"

#include "unity.h"

// =============================================================================
// ContentType tests
// =============================================================================

void test_ContentType_values(void) {
    TEST_ASSERT_EQUAL(0, static_cast<uint8_t>(ndn::ContentType::Blob));
    TEST_ASSERT_EQUAL(1, static_cast<uint8_t>(ndn::ContentType::Link));
    TEST_ASSERT_EQUAL(2, static_cast<uint8_t>(ndn::ContentType::Key));
    TEST_ASSERT_EQUAL(3, static_cast<uint8_t>(ndn::ContentType::Nack));
}

// =============================================================================
// Data ContentType tests
// =============================================================================

void test_Data_contentType_default_is_Blob(void) {
    ndn::Data data;
    TEST_ASSERT_EQUAL(ndn::ContentType::Blob, data.contentType());
}

void test_Data_setContentType(void) {
    ndn::Data data;
    data.setContentType(ndn::ContentType::Link);
    TEST_ASSERT_EQUAL(ndn::ContentType::Link, data.contentType());
}

void test_Data_isLink_returns_true_for_Link(void) {
    ndn::Data data;
    TEST_ASSERT_FALSE(data.isLink());
    data.setContentType(ndn::ContentType::Link);
    TEST_ASSERT_TRUE(data.isLink());
}

void test_Data_ContentType_encodes_and_decodes(void) {
    ndn::Data original;
    original.setName("/test/data");
    original.setContentType(ndn::ContentType::Link);
    original.setContent(std::string_view("test"));
    original.signWithDigestSha256();

    uint8_t buf[512];
    size_t len = 0;
    ndn::Error err = original.encode(buf, sizeof(buf), len);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    auto result = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(result.ok());
    TEST_ASSERT_EQUAL(ndn::ContentType::Link, result.value.contentType());
}

void test_Data_ContentType_Blob_not_encoded(void) {
    ndn::Data data1;
    data1.setName("/test/data");
    data1.setContentType(ndn::ContentType::Blob);
    data1.signWithDigestSha256();

    ndn::Data data2;
    data2.setName("/test/data");
    // ContentType not set (defaults to Blob)
    data2.signWithDigestSha256();

    uint8_t buf1[512], buf2[512];
    size_t len1 = 0, len2 = 0;

    data1.encode(buf1, sizeof(buf1), len1);
    data2.encode(buf2, sizeof(buf2), len2);

    // Both should produce same output (Blob is default, not encoded)
    TEST_ASSERT_EQUAL(len1, len2);
}

// =============================================================================
// Link basic tests
// =============================================================================

void test_Link_default_constructor(void) {
    ndn::Link link;
    TEST_ASSERT_EQUAL(0, link.delegationCount());
}

void test_Link_name_constructor(void) {
    auto nameResult = ndn::Name::fromUri("/test/link");
    TEST_ASSERT_TRUE(nameResult.ok());

    ndn::Link link(nameResult.value);
    TEST_ASSERT_TRUE(link.name().equals(nameResult.value));
}

void test_Link_setName(void) {
    ndn::Link link;
    auto nameResult = ndn::Name::fromUri("/example/link");
    TEST_ASSERT_TRUE(nameResult.ok());

    link.setName(nameResult.value);
    TEST_ASSERT_TRUE(link.name().equals(nameResult.value));
}

void test_Link_setName_from_uri(void) {
    ndn::Link link;
    ndn::Error err = link.setName("/example/link");
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    auto expected = ndn::Name::fromUri("/example/link");
    TEST_ASSERT_TRUE(link.name().equals(expected.value));
}

// =============================================================================
// Link delegation tests
// =============================================================================

void test_Link_addDelegation(void) {
    ndn::Link link;

    auto name1 = ndn::Name::fromUri("/ndn/jp/provider1");
    auto name2 = ndn::Name::fromUri("/ndn/us/provider2");
    TEST_ASSERT_TRUE(name1.ok());
    TEST_ASSERT_TRUE(name2.ok());

    ndn::Error err = link.addDelegation(name1.value);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_EQUAL(1, link.delegationCount());

    err = link.addDelegation(name2.value);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_EQUAL(2, link.delegationCount());
}

void test_Link_addDelegation_from_uri(void) {
    ndn::Link link;

    ndn::Error err = link.addDelegation("/ndn/jp/provider");
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_EQUAL(1, link.delegationCount());
}

void test_Link_addDelegation_duplicate_fails(void) {
    ndn::Link link;

    ndn::Error err = link.addDelegation("/ndn/jp/provider");
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    err = link.addDelegation("/ndn/jp/provider");
    TEST_ASSERT_EQUAL(ndn::Error::InvalidParam, err);
    TEST_ASSERT_EQUAL(1, link.delegationCount());
}

void test_Link_addDelegation_full(void) {
    ndn::Link link;

    // Can add up to LINK_MAX_DELEGATIONS
    for (size_t i = 0; i < ndn::LINK_MAX_DELEGATIONS; ++i) {
        char uri[32];
        snprintf(uri, sizeof(uri), "/ndn/provider%zu", i);
        ndn::Error err = link.addDelegation(uri);
        TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    }

    TEST_ASSERT_EQUAL(ndn::LINK_MAX_DELEGATIONS, link.delegationCount());

    // Full, addition fails
    ndn::Error err = link.addDelegation("/ndn/extra");
    TEST_ASSERT_EQUAL(ndn::Error::Full, err);
}

void test_Link_delegation_by_index(void) {
    ndn::Link link;
    link.addDelegation("/ndn/first");
    link.addDelegation("/ndn/second");
    link.addDelegation("/ndn/third");

    auto first = ndn::Name::fromUri("/ndn/first");
    auto second = ndn::Name::fromUri("/ndn/second");
    auto third = ndn::Name::fromUri("/ndn/third");

    const ndn::Name* d0 = link.delegation(0);
    const ndn::Name* d1 = link.delegation(1);
    const ndn::Name* d2 = link.delegation(2);
    const ndn::Name* d3 = link.delegation(3);

    TEST_ASSERT_NOT_NULL(d0);
    TEST_ASSERT_NOT_NULL(d1);
    TEST_ASSERT_NOT_NULL(d2);
    TEST_ASSERT_NULL(d3);

    TEST_ASSERT_TRUE(d0->equals(first.value));
    TEST_ASSERT_TRUE(d1->equals(second.value));
    TEST_ASSERT_TRUE(d2->equals(third.value));
}

void test_Link_clearDelegations(void) {
    ndn::Link link;
    link.addDelegation("/ndn/first");
    link.addDelegation("/ndn/second");
    TEST_ASSERT_EQUAL(2, link.delegationCount());

    link.clearDelegations();
    TEST_ASSERT_EQUAL(0, link.delegationCount());
}

void test_Link_hasDelegation(void) {
    ndn::Link link;
    link.addDelegation("/ndn/provider1");
    link.addDelegation("/ndn/provider2");

    auto p1 = ndn::Name::fromUri("/ndn/provider1");
    auto p2 = ndn::Name::fromUri("/ndn/provider2");
    auto p3 = ndn::Name::fromUri("/ndn/provider3");

    TEST_ASSERT_TRUE(link.hasDelegation(p1.value));
    TEST_ASSERT_TRUE(link.hasDelegation(p2.value));
    TEST_ASSERT_FALSE(link.hasDelegation(p3.value));
}

// =============================================================================
// Link toData/fromData tests
// =============================================================================

void test_Link_toData_requires_delegations(void) {
    ndn::Link link;
    link.setName("/test/link");

    ndn::Data data;
    ndn::Error err = link.toData(data);
    TEST_ASSERT_EQUAL(ndn::Error::InvalidParam, err);
}

void test_Link_toData(void) {
    ndn::Link link;
    link.setName("/test/link");
    link.addDelegation("/ndn/provider1");
    link.addDelegation("/ndn/provider2");

    ndn::Data data;
    ndn::Error err = link.toData(data);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_EQUAL(ndn::ContentType::Link, data.contentType());
    TEST_ASSERT_TRUE(data.hasContent());

    auto expected = ndn::Name::fromUri("/test/link");
    TEST_ASSERT_TRUE(data.name().equals(expected.value));
}

void test_Link_fromData_invalid_contentType(void) {
    ndn::Data data;
    data.setName("/test/data");
    data.setContentType(ndn::ContentType::Blob);
    data.setContent(std::string_view("test"));

    auto result = ndn::Link::fromData(data);
    TEST_ASSERT_FALSE(result.ok());
    TEST_ASSERT_EQUAL(ndn::Error::InvalidPacket, result.error);
}

void test_Link_fromData_no_content(void) {
    ndn::Data data;
    data.setName("/test/link");
    data.setContentType(ndn::ContentType::Link);
    // No content

    auto result = ndn::Link::fromData(data);
    TEST_ASSERT_FALSE(result.ok());
    TEST_ASSERT_EQUAL(ndn::Error::InvalidPacket, result.error);
}

void test_Link_roundtrip(void) {
    // Create original Link
    ndn::Link original;
    original.setName("/example/link");
    original.addDelegation("/ndn/jp/provider1");
    original.addDelegation("/ndn/us/provider2");
    original.addDelegation("/ndn/eu/provider3");

    // Encode to Data and decode back to Link
    ndn::Data data;
    ndn::Error err = original.toData(data);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    auto result = ndn::Link::fromData(data);
    TEST_ASSERT_TRUE(result.ok());

    ndn::Link& decoded = result.value;
    TEST_ASSERT_TRUE(decoded.name().equals(original.name()));
    TEST_ASSERT_EQUAL(original.delegationCount(), decoded.delegationCount());

    for (size_t i = 0; i < original.delegationCount(); ++i) {
        TEST_ASSERT_TRUE(decoded.delegation(i)->equals(*original.delegation(i)));
    }
}

void test_Link_wire_roundtrip(void) {
    // Create Link
    ndn::Link original;
    original.setName("/example/link");
    original.addDelegation("/ndn/provider1");
    original.addDelegation("/ndn/provider2");

    // Encode to Data
    ndn::Data originalData;
    ndn::Error err = original.toData(originalData);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    originalData.signWithDigestSha256();

    // Encode to wire format
    uint8_t buf[512];
    size_t len = 0;
    err = originalData.encode(buf, sizeof(buf), len);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    // Decode from wire format
    auto dataResult = ndn::Data::fromWire(buf, len);
    TEST_ASSERT_TRUE(dataResult.ok());

    // Convert to Link
    auto linkResult = ndn::Link::fromData(dataResult.value);
    TEST_ASSERT_TRUE(linkResult.ok());

    ndn::Link& decoded = linkResult.value;
    TEST_ASSERT_TRUE(decoded.name().equals(original.name()));
    TEST_ASSERT_EQUAL(original.delegationCount(), decoded.delegationCount());
}

// =============================================================================
// Interest ForwardingHint tests
// =============================================================================

void test_Interest_forwardingHint_initially_empty(void) {
    ndn::Interest interest;
    TEST_ASSERT_EQUAL(0, interest.forwardingHintCount());
    TEST_ASSERT_FALSE(interest.hasForwardingHint());
}

void test_Interest_addForwardingHint(void) {
    ndn::Interest interest;

    auto name1 = ndn::Name::fromUri("/ndn/provider1");
    auto name2 = ndn::Name::fromUri("/ndn/provider2");

    ndn::Error err = interest.addForwardingHint(name1.value);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_EQUAL(1, interest.forwardingHintCount());
    TEST_ASSERT_TRUE(interest.hasForwardingHint());

    err = interest.addForwardingHint(name2.value);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_EQUAL(2, interest.forwardingHintCount());
}

void test_Interest_addForwardingHint_from_uri(void) {
    ndn::Interest interest;

    ndn::Error err = interest.addForwardingHint("/ndn/provider");
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_EQUAL(1, interest.forwardingHintCount());
}

void test_Interest_forwardingHint_by_index(void) {
    ndn::Interest interest;
    interest.addForwardingHint("/ndn/first");
    interest.addForwardingHint("/ndn/second");

    auto first = ndn::Name::fromUri("/ndn/first");
    auto second = ndn::Name::fromUri("/ndn/second");

    const ndn::Name* h0 = interest.forwardingHint(0);
    const ndn::Name* h1 = interest.forwardingHint(1);
    const ndn::Name* h2 = interest.forwardingHint(2);

    TEST_ASSERT_NOT_NULL(h0);
    TEST_ASSERT_NOT_NULL(h1);
    TEST_ASSERT_NULL(h2);

    TEST_ASSERT_TRUE(h0->equals(first.value));
    TEST_ASSERT_TRUE(h1->equals(second.value));
}

void test_Interest_clearForwardingHints(void) {
    ndn::Interest interest;
    interest.addForwardingHint("/ndn/first");
    interest.addForwardingHint("/ndn/second");
    TEST_ASSERT_EQUAL(2, interest.forwardingHintCount());

    interest.clearForwardingHints();
    TEST_ASSERT_EQUAL(0, interest.forwardingHintCount());
    TEST_ASSERT_FALSE(interest.hasForwardingHint());
}

void test_Interest_forwardingHint_encodes_and_decodes(void) {
    ndn::Interest original;
    original.setName("/test/interest");
    original.addForwardingHint("/ndn/provider1");
    original.addForwardingHint("/ndn/provider2");
    original.generateNonce();

    uint8_t buf[512];
    size_t len = 0;
    ndn::Error err = original.encode(buf, sizeof(buf), len);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    auto result = ndn::Interest::fromWire(buf, len);
    TEST_ASSERT_TRUE(result.ok());

    ndn::Interest& decoded = result.value;
    TEST_ASSERT_EQUAL(original.forwardingHintCount(), decoded.forwardingHintCount());

    for (size_t i = 0; i < original.forwardingHintCount(); ++i) {
        TEST_ASSERT_TRUE(decoded.forwardingHint(i)->equals(*original.forwardingHint(i)));
    }
}

void test_Interest_forwardingHint_without_encodes_normally(void) {
    ndn::Interest original;
    original.setName("/test/interest");
    original.generateNonce();
    // No ForwardingHint

    uint8_t buf[512];
    size_t len = 0;
    ndn::Error err = original.encode(buf, sizeof(buf), len);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    auto result = ndn::Interest::fromWire(buf, len);
    TEST_ASSERT_TRUE(result.ok());
    TEST_ASSERT_EQUAL(0, result.value.forwardingHintCount());
}

// =============================================================================
// Integration test: Link to ForwardingHint
// =============================================================================

void test_Link_to_ForwardingHint_integration(void) {
    // Create Link
    ndn::Link link;
    link.setName("/example/link");
    link.addDelegation("/ndn/jp/provider");
    link.addDelegation("/ndn/us/provider");

    // Set as ForwardingHint on Interest
    ndn::Interest interest;
    interest.setName("/data/request");

    for (size_t i = 0; i < link.delegationCount(); ++i) {
        const ndn::Name* delegation = link.delegation(i);
        TEST_ASSERT_NOT_NULL(delegation);
        ndn::Error err = interest.addForwardingHint(*delegation);
        TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    }

    TEST_ASSERT_EQUAL(link.delegationCount(), interest.forwardingHintCount());
}

// =============================================================================
// Test runner
// =============================================================================

void run_link_tests(void) {
    // ContentType tests
    RUN_TEST(test_ContentType_values);

    // Data ContentType tests
    RUN_TEST(test_Data_contentType_default_is_Blob);
    RUN_TEST(test_Data_setContentType);
    RUN_TEST(test_Data_isLink_returns_true_for_Link);
    RUN_TEST(test_Data_ContentType_encodes_and_decodes);
    RUN_TEST(test_Data_ContentType_Blob_not_encoded);

    // Link basic tests
    RUN_TEST(test_Link_default_constructor);
    RUN_TEST(test_Link_name_constructor);
    RUN_TEST(test_Link_setName);
    RUN_TEST(test_Link_setName_from_uri);

    // Link delegation tests
    RUN_TEST(test_Link_addDelegation);
    RUN_TEST(test_Link_addDelegation_from_uri);
    RUN_TEST(test_Link_addDelegation_duplicate_fails);
    RUN_TEST(test_Link_addDelegation_full);
    RUN_TEST(test_Link_delegation_by_index);
    RUN_TEST(test_Link_clearDelegations);
    RUN_TEST(test_Link_hasDelegation);

    // Link toData/fromData tests
    RUN_TEST(test_Link_toData_requires_delegations);
    RUN_TEST(test_Link_toData);
    RUN_TEST(test_Link_fromData_invalid_contentType);
    RUN_TEST(test_Link_fromData_no_content);
    RUN_TEST(test_Link_roundtrip);
    RUN_TEST(test_Link_wire_roundtrip);

    // Interest ForwardingHint tests
    RUN_TEST(test_Interest_forwardingHint_initially_empty);
    RUN_TEST(test_Interest_addForwardingHint);
    RUN_TEST(test_Interest_addForwardingHint_from_uri);
    RUN_TEST(test_Interest_forwardingHint_by_index);
    RUN_TEST(test_Interest_clearForwardingHints);
    RUN_TEST(test_Interest_forwardingHint_encodes_and_decodes);
    RUN_TEST(test_Interest_forwardingHint_without_encodes_normally);

    // Integration tests
    RUN_TEST(test_Link_to_ForwardingHint_integration);
}
