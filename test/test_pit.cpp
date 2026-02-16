#include "ndn/pit.hpp"
#include <cstring>
#include "unity.h"

// =============================================================================
// PitEntry tests
// =============================================================================

void test_PitEntry_face_returns_invalid_for_out_of_range(void) {
    ndn::PitEntry entry;
    TEST_ASSERT_EQUAL(ndn::FACE_ID_INVALID, entry.face(0));
    TEST_ASSERT_EQUAL(ndn::FACE_ID_INVALID, entry.face(100));
}

void test_PitEntry_addFace_and_hasFace(void) {
    ndn::Pit pit;
    ndn::Interest interest;
    interest.setName("/test");
    interest.setNonce(1234);

    ndn::PitEntry* entry = nullptr;
    auto result = pit.insert(interest, 10, &entry);
    TEST_ASSERT_EQUAL(ndn::PitInsertResult::New, result);
    TEST_ASSERT_NOT_NULL(entry);

    TEST_ASSERT_TRUE(entry->hasFace(10));
    TEST_ASSERT_FALSE(entry->hasFace(20));

    TEST_ASSERT_TRUE(entry->addFace(20));
    TEST_ASSERT_TRUE(entry->hasFace(20));
    TEST_ASSERT_EQUAL(2, entry->faceCount());
}

void test_PitEntry_addFace_duplicate_returns_true(void) {
    ndn::Pit pit;
    ndn::Interest interest;
    interest.setName("/test");
    interest.setNonce(1234);

    ndn::PitEntry* entry = nullptr;
    pit.insert(interest, 10, &entry);

    // Adding same Face still succeeds (treated as existing)
    TEST_ASSERT_TRUE(entry->addFace(10));
    TEST_ASSERT_EQUAL(1, entry->faceCount());
}

void test_PitEntry_addFace_respects_max_limit(void) {
    ndn::Pit pit;
    ndn::Interest interest;
    interest.setName("/test");
    interest.setNonce(1234);

    ndn::PitEntry* entry = nullptr;
    pit.insert(interest, 1, &entry);

    // Add up to maximum
    for (ndn::FaceId i = 2; i <= ndn::PIT_MAX_FACES_PER_ENTRY; ++i) {
        TEST_ASSERT_TRUE(entry->addFace(i));
    }
    TEST_ASSERT_EQUAL(ndn::PIT_MAX_FACES_PER_ENTRY, entry->faceCount());

    // Cannot add more
    TEST_ASSERT_FALSE(entry->addFace(100));
}

// =============================================================================
// Pit insert tests
// =============================================================================

void test_Pit_insert_new_entry(void) {
    ndn::Pit pit;

    ndn::Interest interest;
    interest.setName("/test/data");
    interest.setNonce(0x12345678);

    ndn::PitEntry* entry = nullptr;
    auto result = pit.insert(interest, 10, &entry);

    TEST_ASSERT_EQUAL(ndn::PitInsertResult::New, result);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL(1, pit.size());
    TEST_ASSERT_EQUAL(0x12345678, entry->nonce());
    TEST_ASSERT_TRUE(entry->hasFace(10));

    // Verify statistics
    TEST_ASSERT_EQUAL(1, pit.stats().insertions);
}

void test_Pit_insert_aggregation_different_nonce(void) {
    ndn::Pit pit;

    ndn::Interest interest1;
    interest1.setName("/test/data");
    interest1.setNonce(1111);

    ndn::Interest interest2;
    interest2.setName("/test/data");
    interest2.setNonce(2222);  // Different nonce

    ndn::PitEntry* entry1 = nullptr;
    ndn::PitEntry* entry2 = nullptr;

    auto result1 = pit.insert(interest1, 10, &entry1);
    auto result2 = pit.insert(interest2, 20, &entry2);

    TEST_ASSERT_EQUAL(ndn::PitInsertResult::New, result1);
    TEST_ASSERT_EQUAL(ndn::PitInsertResult::Aggregated, result2);
    TEST_ASSERT_EQUAL(entry1, entry2);  // Same entry
    TEST_ASSERT_EQUAL(1, pit.size());

    // Both Faces are registered
    TEST_ASSERT_TRUE(entry1->hasFace(10));
    TEST_ASSERT_TRUE(entry1->hasFace(20));

    // Verify statistics
    TEST_ASSERT_EQUAL(1, pit.stats().insertions);
    TEST_ASSERT_EQUAL(1, pit.stats().aggregations);
}

void test_Pit_insert_duplicate_same_nonce(void) {
    ndn::Pit pit;

    ndn::Interest interest1;
    interest1.setName("/test/data");
    interest1.setNonce(1111);

    ndn::Interest interest2;
    interest2.setName("/test/data");
    interest2.setNonce(1111);  // Same nonce (loop detection)

    auto result1 = pit.insert(interest1, 10, nullptr);
    auto result2 = pit.insert(interest2, 20, nullptr);

    TEST_ASSERT_EQUAL(ndn::PitInsertResult::New, result1);
    TEST_ASSERT_EQUAL(ndn::PitInsertResult::Duplicate, result2);
    TEST_ASSERT_EQUAL(1, pit.size());

    // Verify statistics
    TEST_ASSERT_EQUAL(1, pit.stats().duplicates);
}

void test_Pit_insert_full_table(void) {
    ndn::Pit pit;

    // Fill the table
    for (size_t i = 0; i < ndn::PIT_MAX_ENTRIES; ++i) {
        ndn::Interest interest;
        char uri[32];
        snprintf(uri, sizeof(uri), "/test/%zu", i);
        interest.setName(uri);
        interest.setNonce(static_cast<uint32_t>(i));

        auto result = pit.insert(interest, 10, nullptr);
        TEST_ASSERT_EQUAL(ndn::PitInsertResult::New, result);
    }

    TEST_ASSERT_EQUAL(ndn::PIT_MAX_ENTRIES, pit.size());

    // Try to add one more
    ndn::Interest extra;
    extra.setName("/overflow");
    extra.setNonce(99999);

    auto result = pit.insert(extra, 10, nullptr);
    TEST_ASSERT_EQUAL(ndn::PitInsertResult::Full, result);
}

void test_Pit_insert_without_nonce_uses_zero(void) {
    ndn::Pit pit;

    ndn::Interest interest;
    interest.setName("/test");
    // Do not set nonce

    ndn::PitEntry* entry = nullptr;
    auto result = pit.insert(interest, 10, &entry);

    TEST_ASSERT_EQUAL(ndn::PitInsertResult::New, result);
    TEST_ASSERT_EQUAL(0, entry->nonce());
}

// =============================================================================
// Pit find tests
// =============================================================================

void test_Pit_find_existing_entry(void) {
    ndn::Pit pit;

    ndn::Interest interest;
    interest.setName("/sensor/temp");
    interest.setNonce(5555);

    pit.insert(interest, 10, nullptr);

    auto nameResult = ndn::Name::fromUri("/sensor/temp");
    TEST_ASSERT_TRUE(nameResult.ok());

    ndn::PitEntry* found = pit.find(nameResult.value);
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL(5555, found->nonce());
}

void test_Pit_find_nonexistent_entry(void) {
    ndn::Pit pit;

    ndn::Interest interest;
    interest.setName("/sensor/temp");
    interest.setNonce(5555);

    pit.insert(interest, 10, nullptr);

    auto nameResult = ndn::Name::fromUri("/other/name");
    TEST_ASSERT_TRUE(nameResult.ok());

    ndn::PitEntry* found = pit.find(nameResult.value);
    TEST_ASSERT_NULL(found);
}

void test_Pit_find_const_version(void) {
    ndn::Pit pit;

    ndn::Interest interest;
    interest.setName("/test");
    interest.setNonce(1234);

    pit.insert(interest, 10, nullptr);

    const ndn::Pit& constPit = pit;
    auto nameResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(nameResult.ok());

    const ndn::PitEntry* found = constPit.find(nameResult.value);
    TEST_ASSERT_NOT_NULL(found);
}

// =============================================================================
// Pit remove tests
// =============================================================================

void test_Pit_remove_by_pointer(void) {
    ndn::Pit pit;

    ndn::Interest interest;
    interest.setName("/test");
    interest.setNonce(1234);

    ndn::PitEntry* entry = nullptr;
    pit.insert(interest, 10, &entry);
    TEST_ASSERT_EQUAL(1, pit.size());

    pit.remove(entry);
    TEST_ASSERT_EQUAL(0, pit.size());

    // Cannot find by same name after removal
    auto nameResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(nameResult.ok());
    TEST_ASSERT_NULL(pit.find(nameResult.value));
}

void test_Pit_remove_by_name(void) {
    ndn::Pit pit;

    ndn::Interest interest;
    interest.setName("/test/remove");
    interest.setNonce(1234);

    pit.insert(interest, 10, nullptr);
    TEST_ASSERT_EQUAL(1, pit.size());

    auto nameResult = ndn::Name::fromUri("/test/remove");
    TEST_ASSERT_TRUE(nameResult.ok());

    pit.remove(nameResult.value);
    TEST_ASSERT_EQUAL(0, pit.size());
}

void test_Pit_remove_nonexistent_does_nothing(void) {
    ndn::Pit pit;

    ndn::Interest interest;
    interest.setName("/test");
    interest.setNonce(1234);

    pit.insert(interest, 10, nullptr);

    auto nameResult = ndn::Name::fromUri("/nonexistent");
    TEST_ASSERT_TRUE(nameResult.ok());

    pit.remove(nameResult.value);
    TEST_ASSERT_EQUAL(1, pit.size());  // No change
}

void test_Pit_remove_null_pointer_does_nothing(void) {
    ndn::Pit pit;

    ndn::Interest interest;
    interest.setName("/test");
    interest.setNonce(1234);

    pit.insert(interest, 10, nullptr);

    pit.remove(nullptr);
    TEST_ASSERT_EQUAL(1, pit.size());  // No change
}

// =============================================================================
// Pit timeout tests
// =============================================================================

void test_Pit_processTimeouts_removes_expired_entries(void) {
    ndn::Pit pit;

    ndn::Interest interest1;
    interest1.setName("/short");
    interest1.setNonce(1111);
    interest1.setLifetime(1000);  // 1秒

    ndn::Interest interest2;
    interest2.setName("/long");
    interest2.setNonce(2222);
    interest2.setLifetime(10000);  // 10秒

    ndn::PitEntry* entry1 = nullptr;
    ndn::PitEntry* entry2 = nullptr;
    pit.insert(interest1, 10, &entry1);
    pit.insert(interest2, 20, &entry2);
    TEST_ASSERT_EQUAL(2, pit.size());

    // Process timeout at a time after entry1 expires but before entry2 expires
    ndn::TimeMs timeoutTime = entry1->expireTime() + 100;
    pit.processTimeouts(timeoutTime);

    // short timed out, long remains
    TEST_ASSERT_EQUAL(1, pit.size());

    auto shortName = ndn::Name::fromUri("/short");
    auto longName = ndn::Name::fromUri("/long");
    TEST_ASSERT_TRUE(shortName.ok());
    TEST_ASSERT_TRUE(longName.ok());

    TEST_ASSERT_NULL(pit.find(shortName.value));
    TEST_ASSERT_NOT_NULL(pit.find(longName.value));

    // Verify statistics
    TEST_ASSERT_EQUAL(1, pit.stats().timeouts);
}

void test_Pit_processTimeouts_calls_callback(void) {
    ndn::Pit pit;

    ndn::Interest interest;
    interest.setName("/callback/test");
    interest.setNonce(9999);
    interest.setLifetime(1000);

    ndn::PitEntry* entry = nullptr;
    pit.insert(interest, 10, &entry);

    ndn::TimeMs timeoutTime = entry->expireTime() + 100;

    int callbackCount = 0;
    ndn::Name timedOutName;

    pit.processTimeouts(timeoutTime, [&](const ndn::PitEntry& e) {
        callbackCount++;
        timedOutName = e.name();
    });

    TEST_ASSERT_EQUAL(1, callbackCount);

    auto expectedName = ndn::Name::fromUri("/callback/test");
    TEST_ASSERT_TRUE(expectedName.ok());
    TEST_ASSERT_TRUE(timedOutName.equals(expectedName.value));
}

void test_Pit_processTimeouts_no_callback_is_ok(void) {
    ndn::Pit pit;

    ndn::Interest interest;
    interest.setName("/test");
    interest.setNonce(1234);
    interest.setLifetime(1000);

    ndn::PitEntry* entry = nullptr;
    pit.insert(interest, 10, &entry);

    ndn::TimeMs timeoutTime = entry->expireTime() + 100;

    // Works without callback
    pit.processTimeouts(timeoutTime);
    TEST_ASSERT_EQUAL(0, pit.size());
}

// =============================================================================
// Pit entry expiration time
// =============================================================================

void test_Pit_entry_expireTime_is_set(void) {
    ndn::Pit pit;

    ndn::Interest interest;
    interest.setName("/test");
    interest.setNonce(1234);
    interest.setLifetime(3000);  // 3秒

    ndn::PitEntry* entry = nullptr;
    pit.insert(interest, 10, &entry);

    // expireTime is set to currentTimeMs() + lifetime
    // The exact value depends on currentTimeMs() at runtime,
    // but the 3000ms lifetime should be reflected
    TEST_ASSERT_TRUE(entry->expireTime() > 0);
}

// =============================================================================
// Pit reuse after remove
// =============================================================================

void test_Pit_reuses_slot_after_remove(void) {
    ndn::Pit pit;

    // Add an entry and remove it
    ndn::Interest interest1;
    interest1.setName("/first");
    interest1.setNonce(1111);

    ndn::PitEntry* entry1 = nullptr;
    pit.insert(interest1, 10, &entry1);
    pit.remove(entry1);

    TEST_ASSERT_EQUAL(0, pit.size());

    // Add a new entry
    ndn::Interest interest2;
    interest2.setName("/second");
    interest2.setNonce(2222);

    ndn::PitEntry* entry2 = nullptr;
    auto result = pit.insert(interest2, 20, &entry2);

    TEST_ASSERT_EQUAL(ndn::PitInsertResult::New, result);
    TEST_ASSERT_EQUAL(1, pit.size());
}

// =============================================================================
// Test runner
// =============================================================================

void run_pit_tests(void) {
    // PitEntry tests
    RUN_TEST(test_PitEntry_face_returns_invalid_for_out_of_range);
    RUN_TEST(test_PitEntry_addFace_and_hasFace);
    RUN_TEST(test_PitEntry_addFace_duplicate_returns_true);
    RUN_TEST(test_PitEntry_addFace_respects_max_limit);

    // Pit insert tests
    RUN_TEST(test_Pit_insert_new_entry);
    RUN_TEST(test_Pit_insert_aggregation_different_nonce);
    RUN_TEST(test_Pit_insert_duplicate_same_nonce);
    RUN_TEST(test_Pit_insert_full_table);
    RUN_TEST(test_Pit_insert_without_nonce_uses_zero);

    // Pit find tests
    RUN_TEST(test_Pit_find_existing_entry);
    RUN_TEST(test_Pit_find_nonexistent_entry);
    RUN_TEST(test_Pit_find_const_version);

    // Pit remove tests
    RUN_TEST(test_Pit_remove_by_pointer);
    RUN_TEST(test_Pit_remove_by_name);
    RUN_TEST(test_Pit_remove_nonexistent_does_nothing);
    RUN_TEST(test_Pit_remove_null_pointer_does_nothing);

    // Pit timeout tests
    RUN_TEST(test_Pit_processTimeouts_removes_expired_entries);
    RUN_TEST(test_Pit_processTimeouts_calls_callback);
    RUN_TEST(test_Pit_processTimeouts_no_callback_is_ok);

    // Expire time test
    RUN_TEST(test_Pit_entry_expireTime_is_set);

    // Reuse test
    RUN_TEST(test_Pit_reuses_slot_after_remove);
}
