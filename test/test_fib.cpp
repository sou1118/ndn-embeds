#include "ndn/fib.hpp"
#include <cstring>
#include "unity.h"

// =============================================================================
// FibEntry tests
// =============================================================================

void test_FibEntry_nexthop_returns_invalid_for_out_of_range(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 0);

    const ndn::FibEntry* entry = fib.findExact(prefixResult.value);
    TEST_ASSERT_NOT_NULL(entry);

    // Out-of-range index
    const ndn::FibNexthop& nh = entry->nexthop(100);
    TEST_ASSERT_EQUAL(ndn::FACE_ID_INVALID, nh.faceId);
}

void test_FibEntry_addNexthop_and_nexthopCount(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 5);

    ndn::FibEntry* entry = fib.findExact(prefixResult.value);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL(1, entry->nexthopCount());

    // Add second nexthop
    TEST_ASSERT_TRUE(entry->addNexthop(20, 10));
    TEST_ASSERT_EQUAL(2, entry->nexthopCount());

    // Verify nexthop contents
    TEST_ASSERT_EQUAL(10, entry->nexthop(0).faceId);
    TEST_ASSERT_EQUAL(5, entry->nexthop(0).cost);
    TEST_ASSERT_EQUAL(20, entry->nexthop(1).faceId);
    TEST_ASSERT_EQUAL(10, entry->nexthop(1).cost);
}

void test_FibEntry_addNexthop_updates_existing(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 5);

    ndn::FibEntry* entry = fib.findExact(prefixResult.value);
    TEST_ASSERT_NOT_NULL(entry);

    // Adding same faceId with different cost -> updated
    TEST_ASSERT_TRUE(entry->addNexthop(10, 100));
    TEST_ASSERT_EQUAL(1, entry->nexthopCount());     // Count unchanged
    TEST_ASSERT_EQUAL(100, entry->nexthop(0).cost);  // Cost updated
}

void test_FibEntry_addNexthop_respects_max_limit(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 1, 0);

    ndn::FibEntry* entry = fib.findExact(prefixResult.value);
    TEST_ASSERT_NOT_NULL(entry);

    // Add up to maximum
    for (ndn::FaceId i = 2; i <= ndn::FIB_MAX_NEXTHOPS; ++i) {
        TEST_ASSERT_TRUE(entry->addNexthop(i, 0));
    }
    TEST_ASSERT_EQUAL(ndn::FIB_MAX_NEXTHOPS, entry->nexthopCount());

    // Cannot add more
    TEST_ASSERT_FALSE(entry->addNexthop(100, 0));
}

void test_FibEntry_removeNexthop(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 0);

    ndn::FibEntry* entry = fib.findExact(prefixResult.value);
    entry->addNexthop(20, 0);
    entry->addNexthop(30, 0);
    TEST_ASSERT_EQUAL(3, entry->nexthopCount());

    // Remove middle nexthop
    TEST_ASSERT_TRUE(entry->removeNexthop(20));
    TEST_ASSERT_EQUAL(2, entry->nexthopCount());

    // Remove non-existent nexthop
    TEST_ASSERT_FALSE(entry->removeNexthop(99));
}

// =============================================================================
// Fib addRoute tests
// =============================================================================

void test_Fib_addRoute_new_entry(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/sensor/data");
    TEST_ASSERT_TRUE(prefixResult.ok());

    auto err = fib.addRoute(prefixResult.value, 10, 5);

    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_EQUAL(1, fib.size());

    const ndn::FibEntry* entry = fib.findExact(prefixResult.value);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL(1, entry->nexthopCount());
    TEST_ASSERT_EQUAL(10, entry->nexthop(0).faceId);
    TEST_ASSERT_EQUAL(5, entry->nexthop(0).cost);
}

void test_Fib_addRoute_adds_nexthop_to_existing(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/sensor/data");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 5);
    auto err = fib.addRoute(prefixResult.value, 20, 10);

    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_EQUAL(1, fib.size());  // Entry count unchanged

    const ndn::FibEntry* entry = fib.findExact(prefixResult.value);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL(2, entry->nexthopCount());
}

void test_Fib_addRoute_full_table(void) {
    ndn::Fib fib;

    // Fill the table
    for (size_t i = 0; i < ndn::FIB_MAX_ENTRIES; ++i) {
        char uri[32];
        snprintf(uri, sizeof(uri), "/prefix/%zu", i);
        auto prefixResult = ndn::Name::fromUri(uri);
        TEST_ASSERT_TRUE(prefixResult.ok());

        auto err = fib.addRoute(prefixResult.value, 10, 0);
        TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    }

    TEST_ASSERT_EQUAL(ndn::FIB_MAX_ENTRIES, fib.size());

    // Try to add one more
    auto overflowResult = ndn::Name::fromUri("/overflow");
    TEST_ASSERT_TRUE(overflowResult.ok());

    auto err = fib.addRoute(overflowResult.value, 10, 0);
    TEST_ASSERT_EQUAL(ndn::Error::Full, err);
}

void test_Fib_addRoute_full_nexthops(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(prefixResult.ok());

    // Add nexthops up to maximum
    for (ndn::FaceId i = 1; i <= ndn::FIB_MAX_NEXTHOPS; ++i) {
        auto err = fib.addRoute(prefixResult.value, i, 0);
        TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    }

    // Adding more returns Full
    auto err = fib.addRoute(prefixResult.value, 100, 0);
    TEST_ASSERT_EQUAL(ndn::Error::Full, err);
}

// =============================================================================
// Fib removeRoute tests
// =============================================================================

void test_Fib_removeRoute_single_nexthop(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 0);
    TEST_ASSERT_EQUAL(1, fib.size());

    // Remove nexthop -> entry is also removed
    fib.removeRoute(prefixResult.value, 10);
    TEST_ASSERT_EQUAL(0, fib.size());
    TEST_ASSERT_NULL(fib.findExact(prefixResult.value));
}

void test_Fib_removeRoute_one_of_multiple_nexthops(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 0);
    fib.addRoute(prefixResult.value, 20, 0);
    TEST_ASSERT_EQUAL(1, fib.size());

    // Remove one nexthop
    fib.removeRoute(prefixResult.value, 10);

    // Entry still exists
    TEST_ASSERT_EQUAL(1, fib.size());
    const ndn::FibEntry* entry = fib.findExact(prefixResult.value);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL(1, entry->nexthopCount());
    TEST_ASSERT_EQUAL(20, entry->nexthop(0).faceId);
}

void test_Fib_removeRoute_entire_prefix(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 0);
    fib.addRoute(prefixResult.value, 20, 0);
    TEST_ASSERT_EQUAL(1, fib.size());

    // Remove entire prefix
    fib.removeRoute(prefixResult.value);
    TEST_ASSERT_EQUAL(0, fib.size());
    TEST_ASSERT_NULL(fib.findExact(prefixResult.value));
}

void test_Fib_removeRoute_nonexistent_does_nothing(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 0);

    auto nonexistentResult = ndn::Name::fromUri("/nonexistent");
    TEST_ASSERT_TRUE(nonexistentResult.ok());

    // Remove non-existent prefix
    fib.removeRoute(nonexistentResult.value, 10);
    fib.removeRoute(nonexistentResult.value);

    TEST_ASSERT_EQUAL(1, fib.size());  // No change
}

// =============================================================================
// Fib removeFace tests
// =============================================================================

void test_Fib_removeFace_removes_from_all_entries(void) {
    ndn::Fib fib;

    auto prefix1Result = ndn::Name::fromUri("/prefix/1");
    auto prefix2Result = ndn::Name::fromUri("/prefix/2");
    TEST_ASSERT_TRUE(prefix1Result.ok());
    TEST_ASSERT_TRUE(prefix2Result.ok());

    // Add same faceId to multiple entries
    fib.addRoute(prefix1Result.value, 10, 0);
    fib.addRoute(prefix1Result.value, 20, 0);
    fib.addRoute(prefix2Result.value, 10, 0);
    fib.addRoute(prefix2Result.value, 30, 0);

    TEST_ASSERT_EQUAL(2, fib.size());

    // Remove faceId=10 from all entries
    fib.removeFace(10);

    // faceId=10 removed from both entries
    const ndn::FibEntry* entry1 = fib.findExact(prefix1Result.value);
    const ndn::FibEntry* entry2 = fib.findExact(prefix2Result.value);
    TEST_ASSERT_NOT_NULL(entry1);
    TEST_ASSERT_NOT_NULL(entry2);
    TEST_ASSERT_EQUAL(1, entry1->nexthopCount());
    TEST_ASSERT_EQUAL(20, entry1->nexthop(0).faceId);
    TEST_ASSERT_EQUAL(1, entry2->nexthopCount());
    TEST_ASSERT_EQUAL(30, entry2->nexthop(0).faceId);
}

void test_Fib_removeFace_removes_entry_if_no_nexthops(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 0);
    TEST_ASSERT_EQUAL(1, fib.size());

    // Remove face with only nexthop -> entry also removed
    fib.removeFace(10);
    TEST_ASSERT_EQUAL(0, fib.size());
}

// =============================================================================
// Fib findExact tests
// =============================================================================

void test_Fib_findExact_existing_entry(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/sensor/temp");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 0);

    const ndn::FibEntry* entry = fib.findExact(prefixResult.value);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_TRUE(entry->prefix().equals(prefixResult.value));
}

void test_Fib_findExact_nonexistent_entry(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/sensor/temp");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 0);

    auto otherResult = ndn::Name::fromUri("/other/prefix");
    TEST_ASSERT_TRUE(otherResult.ok());

    const ndn::FibEntry* entry = fib.findExact(otherResult.value);
    TEST_ASSERT_NULL(entry);
}

void test_Fib_findExact_mutable_version(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 0);

    // mutable版
    ndn::FibEntry* entry = fib.findExact(prefixResult.value);
    TEST_ASSERT_NOT_NULL(entry);

    // Can add nexthop
    TEST_ASSERT_TRUE(entry->addNexthop(20, 0));
    TEST_ASSERT_EQUAL(2, entry->nexthopCount());
}

// =============================================================================
// Fib findLongestMatch tests
// =============================================================================

void test_Fib_findLongestMatch_exact_match(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/sensor/temp");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 0);

    // Exact match
    const ndn::FibEntry* entry = fib.findLongestMatch(prefixResult.value);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_TRUE(entry->prefix().equals(prefixResult.value));
}

void test_Fib_findLongestMatch_prefix_match(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/sensor");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 0);

    // /sensor/temp matches /sensor
    auto nameResult = ndn::Name::fromUri("/sensor/temp");
    TEST_ASSERT_TRUE(nameResult.ok());

    const ndn::FibEntry* entry = fib.findLongestMatch(nameResult.value);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_TRUE(entry->prefix().equals(prefixResult.value));
}

void test_Fib_findLongestMatch_longest_prefix(void) {
    ndn::Fib fib;

    auto shortPrefixResult = ndn::Name::fromUri("/sensor");
    auto longPrefixResult = ndn::Name::fromUri("/sensor/temp");
    TEST_ASSERT_TRUE(shortPrefixResult.ok());
    TEST_ASSERT_TRUE(longPrefixResult.ok());

    fib.addRoute(shortPrefixResult.value, 10, 0);
    fib.addRoute(longPrefixResult.value, 20, 0);

    // /sensor/temp/value matches /sensor/temp (longest match)
    auto nameResult = ndn::Name::fromUri("/sensor/temp/value");
    TEST_ASSERT_TRUE(nameResult.ok());

    const ndn::FibEntry* entry = fib.findLongestMatch(nameResult.value);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_TRUE(entry->prefix().equals(longPrefixResult.value));
    TEST_ASSERT_EQUAL(20, entry->nexthop(0).faceId);
}

void test_Fib_findLongestMatch_no_match(void) {
    ndn::Fib fib;

    auto prefixResult = ndn::Name::fromUri("/sensor");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fib.addRoute(prefixResult.value, 10, 0);

    // /other/name does not match /sensor
    auto nameResult = ndn::Name::fromUri("/other/name");
    TEST_ASSERT_TRUE(nameResult.ok());

    const ndn::FibEntry* entry = fib.findLongestMatch(nameResult.value);
    TEST_ASSERT_NULL(entry);
}

void test_Fib_findLongestMatch_root_prefix(void) {
    ndn::Fib fib;

    // Register root prefix (empty Name)
    ndn::Name rootPrefix;  // Empty Name
    fib.addRoute(rootPrefix, 10, 0);

    // Any name matches
    auto nameResult = ndn::Name::fromUri("/any/name/here");
    TEST_ASSERT_TRUE(nameResult.ok());

    const ndn::FibEntry* entry = fib.findLongestMatch(nameResult.value);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_TRUE(entry->prefix().empty());
}

// =============================================================================
// Fib slot reuse tests
// =============================================================================

void test_Fib_reuses_slot_after_remove(void) {
    ndn::Fib fib;

    auto prefix1Result = ndn::Name::fromUri("/first");
    TEST_ASSERT_TRUE(prefix1Result.ok());

    fib.addRoute(prefix1Result.value, 10, 0);
    fib.removeRoute(prefix1Result.value);
    TEST_ASSERT_EQUAL(0, fib.size());

    // Add a new entry
    auto prefix2Result = ndn::Name::fromUri("/second");
    TEST_ASSERT_TRUE(prefix2Result.ok());

    auto err = fib.addRoute(prefix2Result.value, 20, 0);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_EQUAL(1, fib.size());
}

// =============================================================================
// Test runner
// =============================================================================

void run_fib_tests(void) {
    // FibEntry tests
    RUN_TEST(test_FibEntry_nexthop_returns_invalid_for_out_of_range);
    RUN_TEST(test_FibEntry_addNexthop_and_nexthopCount);
    RUN_TEST(test_FibEntry_addNexthop_updates_existing);
    RUN_TEST(test_FibEntry_addNexthop_respects_max_limit);
    RUN_TEST(test_FibEntry_removeNexthop);

    // Fib addRoute tests
    RUN_TEST(test_Fib_addRoute_new_entry);
    RUN_TEST(test_Fib_addRoute_adds_nexthop_to_existing);
    RUN_TEST(test_Fib_addRoute_full_table);
    RUN_TEST(test_Fib_addRoute_full_nexthops);

    // Fib removeRoute tests
    RUN_TEST(test_Fib_removeRoute_single_nexthop);
    RUN_TEST(test_Fib_removeRoute_one_of_multiple_nexthops);
    RUN_TEST(test_Fib_removeRoute_entire_prefix);
    RUN_TEST(test_Fib_removeRoute_nonexistent_does_nothing);

    // Fib removeFace tests
    RUN_TEST(test_Fib_removeFace_removes_from_all_entries);
    RUN_TEST(test_Fib_removeFace_removes_entry_if_no_nexthops);

    // Fib findExact tests
    RUN_TEST(test_Fib_findExact_existing_entry);
    RUN_TEST(test_Fib_findExact_nonexistent_entry);
    RUN_TEST(test_Fib_findExact_mutable_version);

    // Fib findLongestMatch tests
    RUN_TEST(test_Fib_findLongestMatch_exact_match);
    RUN_TEST(test_Fib_findLongestMatch_prefix_match);
    RUN_TEST(test_Fib_findLongestMatch_longest_prefix);
    RUN_TEST(test_Fib_findLongestMatch_no_match);
    RUN_TEST(test_Fib_findLongestMatch_root_prefix);

    // Slot reuse tests
    RUN_TEST(test_Fib_reuses_slot_after_remove);
}
