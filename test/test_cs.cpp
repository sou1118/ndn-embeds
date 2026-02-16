#include "ndn/cs.hpp"
#include <cstring>
#include "unity.h"

// =============================================================================
// CsEntry tests
// =============================================================================

void test_CsEntry_isFresh_returns_true_when_staleTime_is_zero(void) {
    // staleTime = 0 means no FreshnessPeriod = always fresh
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data;
    data.setName("/test");
    // Do not set FreshnessPeriod

    cs.insert(data, 1000);

    auto entry = cs.find(data.name(), false, 1000);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL(0, entry->staleTime());
    TEST_ASSERT_TRUE(entry->isFresh(0));
    TEST_ASSERT_TRUE(entry->isFresh(1000000));  // Fresh at any time
}

void test_CsEntry_isFresh_returns_true_when_before_staleTime(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data;
    data.setName("/test");
    data.setFreshnessPeriod(5000);  // 5秒

    ndn::TimeMs now = 10000;
    cs.insert(data, now);

    auto entry = cs.find(data.name(), false, now);
    TEST_ASSERT_NOT_NULL(entry);
    // staleTime = now + freshnessPeriod = 15000
    TEST_ASSERT_EQUAL(15000, entry->staleTime());
    TEST_ASSERT_TRUE(entry->isFresh(10000));
    TEST_ASSERT_TRUE(entry->isFresh(14999));
}

void test_CsEntry_isFresh_returns_false_when_at_or_after_staleTime(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data;
    data.setName("/test");
    data.setFreshnessPeriod(5000);

    ndn::TimeMs now = 10000;
    cs.insert(data, now);

    auto entry = cs.find(data.name(), false, now);
    TEST_ASSERT_NOT_NULL(entry);
    // staleTime = 15000
    TEST_ASSERT_FALSE(entry->isFresh(15000));
    TEST_ASSERT_FALSE(entry->isFresh(20000));
}

// =============================================================================
// ContentStore insert tests
// =============================================================================

void test_ContentStore_insert_new_entry(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data;
    data.setName("/sensor/temp");
    data.setContent("25.5");

    auto err = cs.insert(data, 1000);

    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_EQUAL(1, cs.size());
    TEST_ASSERT_EQUAL(1, cs.stats().insertions);
}

void test_ContentStore_insert_updates_existing_entry(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data1;
    data1.setName("/sensor/temp");
    data1.setContent("25.5");

    ndn::Data data2;
    data2.setName("/sensor/temp");
    data2.setContent("26.0");  // Updated content

    cs.insert(data1, 1000);
    cs.insert(data2, 2000);

    TEST_ASSERT_EQUAL(1, cs.size());  // Size unchanged

    auto entry = cs.find(data1.name(), false, 2000);
    TEST_ASSERT_NOT_NULL(entry);

    // Content has been updated
    TEST_ASSERT_EQUAL(4, entry->data().contentSize());
    TEST_ASSERT_EQUAL_MEMORY("26.0", entry->data().content(), 4);
}

void test_ContentStore_insert_sets_staleTime_with_freshnessPeriod(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data;
    data.setName("/test");
    data.setFreshnessPeriod(3000);

    ndn::TimeMs now = 5000;
    cs.insert(data, now);

    auto entry = cs.find(data.name(), false, now);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL(8000, entry->staleTime());  // 5000 + 3000
}

void test_ContentStore_insert_sets_staleTime_zero_without_freshnessPeriod(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data;
    data.setName("/test");
    // No FreshnessPeriod

    cs.insert(data, 5000);

    auto entry = cs.find(data.name(), false, 5000);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL(0, entry->staleTime());
}

void test_ContentStore_insert_fills_to_capacity(void) {
    ndn::ContentStore cs;
    cs.init(ndn::CS_MANET_ENTRIES);

    for (size_t i = 0; i < ndn::CS_MANET_ENTRIES; ++i) {
        ndn::Data data;
        char uri[32];
        snprintf(uri, sizeof(uri), "/data/%zu", i);
        data.setName(uri);

        auto err = cs.insert(data, static_cast<ndn::TimeMs>(i * 100));
        TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    }

    TEST_ASSERT_EQUAL(ndn::CS_MANET_ENTRIES, cs.size());
    TEST_ASSERT_EQUAL(ndn::CS_MANET_ENTRIES, cs.capacity());
}

// =============================================================================
// ContentStore find tests
// =============================================================================

void test_ContentStore_find_existing_entry(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data;
    data.setName("/hello/world");
    data.setContent("test content");

    cs.insert(data, 1000);

    auto nameResult = ndn::Name::fromUri("/hello/world");
    TEST_ASSERT_TRUE(nameResult.ok());

    auto entry = cs.find(nameResult.value, false, 1000);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL_MEMORY("test content", entry->data().content(), 12);

    TEST_ASSERT_EQUAL(1, cs.stats().hits);
}

void test_ContentStore_find_nonexistent_entry(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data;
    data.setName("/hello/world");
    cs.insert(data, 1000);

    auto nameResult = ndn::Name::fromUri("/other/name");
    TEST_ASSERT_TRUE(nameResult.ok());

    auto entry = cs.find(nameResult.value, false, 1000);
    TEST_ASSERT_NULL(entry);

    TEST_ASSERT_EQUAL(1, cs.stats().misses);
}

void test_ContentStore_find_mustBeFresh_returns_fresh_entry(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data;
    data.setName("/fresh/data");
    data.setFreshnessPeriod(5000);

    ndn::TimeMs insertTime = 10000;
    cs.insert(data, insertTime);

    // Search within fresh period
    auto entry = cs.find(data.name(), true, 12000);
    TEST_ASSERT_NOT_NULL(entry);
}

void test_ContentStore_find_mustBeFresh_returns_null_for_stale_entry(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data;
    data.setName("/stale/data");
    data.setFreshnessPeriod(5000);

    ndn::TimeMs insertTime = 10000;
    cs.insert(data, insertTime);

    // Search after stale (mustBeFresh = true)
    auto entry = cs.find(data.name(), true, 20000);
    TEST_ASSERT_NULL(entry);
    TEST_ASSERT_EQUAL(1, cs.stats().misses);
}

void test_ContentStore_find_mustBeFresh_false_returns_stale_entry(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data;
    data.setName("/stale/data");
    data.setFreshnessPeriod(5000);

    ndn::TimeMs insertTime = 10000;
    cs.insert(data, insertTime);

    // Returns stale entry when mustBeFresh = false
    auto entry = cs.find(data.name(), false, 20000);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL(1, cs.stats().hits);
}

void test_ContentStore_find_updates_lastUsed(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data1;
    data1.setName("/first");
    ndn::Data data2;
    data2.setName("/second");

    cs.insert(data1, 1000);
    cs.insert(data2, 2000);

    // Search for data1 to update lastUsed
    cs.find(data1.name(), false, 5000);

    // After this, data2 should be the LRU candidate (verified in LRU eviction test)
    TEST_ASSERT_EQUAL(1, cs.stats().hits);  // 1 find
}

// =============================================================================
// ContentStore remove tests
// =============================================================================

void test_ContentStore_remove_existing_entry(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data;
    data.setName("/to/remove");
    cs.insert(data, 1000);

    TEST_ASSERT_EQUAL(1, cs.size());

    auto nameResult = ndn::Name::fromUri("/to/remove");
    TEST_ASSERT_TRUE(nameResult.ok());

    cs.remove(nameResult.value);

    TEST_ASSERT_EQUAL(0, cs.size());
    TEST_ASSERT_NULL(cs.find(nameResult.value, false, 1000));
}

void test_ContentStore_remove_nonexistent_does_nothing(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data;
    data.setName("/existing");
    cs.insert(data, 1000);

    auto nameResult = ndn::Name::fromUri("/nonexistent");
    TEST_ASSERT_TRUE(nameResult.ok());

    cs.remove(nameResult.value);

    TEST_ASSERT_EQUAL(1, cs.size());  // No change
}

// =============================================================================
// ContentStore evictStale tests
// =============================================================================

void test_ContentStore_evictStale_removes_stale_entries(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data staleData;
    staleData.setName("/stale");
    staleData.setFreshnessPeriod(1000);

    ndn::Data freshData;
    freshData.setName("/fresh");
    freshData.setFreshnessPeriod(10000);

    ndn::Data noExpireData;
    noExpireData.setName("/no-expire");
    // No FreshnessPeriod

    ndn::TimeMs insertTime = 5000;
    cs.insert(staleData, insertTime);
    cs.insert(freshData, insertTime);
    cs.insert(noExpireData, insertTime);

    TEST_ASSERT_EQUAL(3, cs.size());

    // staleData has staleTime = 6000, freshData has staleTime = 15000
    // evict at now = 8000
    cs.evictStale(8000);

    TEST_ASSERT_EQUAL(2, cs.size());  // staleData was removed

    auto staleName = ndn::Name::fromUri("/stale");
    auto freshName = ndn::Name::fromUri("/fresh");
    auto noExpireName = ndn::Name::fromUri("/no-expire");
    TEST_ASSERT_TRUE(staleName.ok());
    TEST_ASSERT_TRUE(freshName.ok());
    TEST_ASSERT_TRUE(noExpireName.ok());

    TEST_ASSERT_NULL(cs.find(staleName.value, false, 8000));
    TEST_ASSERT_NOT_NULL(cs.find(freshName.value, false, 8000));
    TEST_ASSERT_NOT_NULL(cs.find(noExpireName.value, false, 8000));

    TEST_ASSERT_EQUAL(1, cs.stats().evictions);  // 1 evicted
}

void test_ContentStore_evictStale_does_nothing_when_all_fresh(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data;
    data.setName("/fresh");
    data.setFreshnessPeriod(10000);

    cs.insert(data, 5000);

    cs.evictStale(6000);  // Still fresh

    TEST_ASSERT_EQUAL(1, cs.size());
    TEST_ASSERT_EQUAL(0, cs.stats().evictions);
}

// =============================================================================
// LRU eviction tests
// =============================================================================

void test_ContentStore_lru_eviction_removes_oldest_used(void) {
    ndn::ContentStore cs;
    cs.init(ndn::CS_MANET_ENTRIES);

    // Fill the table
    for (size_t i = 0; i < ndn::CS_MANET_ENTRIES; ++i) {
        ndn::Data data;
        char uri[32];
        snprintf(uri, sizeof(uri), "/data/%zu", i);
        data.setName(uri);

        // Each data inserted at different time (lastUsed also set)
        cs.insert(data, static_cast<ndn::TimeMs>(i * 100));
    }

    TEST_ASSERT_EQUAL(ndn::CS_MANET_ENTRIES, cs.size());

    // First entry (/data/0) has the oldest lastUsed

    // Insert new data -> LRU eviction occurs
    ndn::Data newData;
    newData.setName("/data/new");

    auto err = cs.insert(newData, 100000);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    TEST_ASSERT_EQUAL(ndn::CS_MANET_ENTRIES, cs.size());  // Size unchanged
    TEST_ASSERT_EQUAL(1, cs.stats().evictions);

    // /data/0 has been evicted
    auto oldName = ndn::Name::fromUri("/data/0");
    TEST_ASSERT_TRUE(oldName.ok());
    TEST_ASSERT_NULL(cs.find(oldName.value, false, 100000));

    // /data/new exists
    auto newName = ndn::Name::fromUri("/data/new");
    TEST_ASSERT_TRUE(newName.ok());
    TEST_ASSERT_NOT_NULL(cs.find(newName.value, false, 100000));
}

void test_ContentStore_lru_eviction_considers_find_access(void) {
    ndn::ContentStore cs;
    cs.init(ndn::CS_MANET_ENTRIES);

    // Create two entries
    ndn::Data data1;
    data1.setName("/data/1");
    ndn::Data data2;
    data2.setName("/data/2");

    // Insert data1 first
    cs.insert(data1, 1000);
    // Insert data2 later
    cs.insert(data2, 2000);

    // Fill the rest
    for (size_t i = 3; i <= ndn::CS_MANET_ENTRIES; ++i) {
        ndn::Data data;
        char uri[32];
        snprintf(uri, sizeof(uri), "/data/%zu", i);
        data.setName(uri);
        cs.insert(data, static_cast<ndn::TimeMs>(i * 1000));
    }

    TEST_ASSERT_EQUAL(ndn::CS_MANET_ENTRIES, cs.size());

    // Access data1 to update lastUsed
    cs.find(data1.name(), false, 50000);

    // Insert new data -> LRU eviction occurs
    // data2 should have the oldest lastUsed
    ndn::Data newData;
    newData.setName("/data/new");
    cs.insert(newData, 60000);

    // data2 has been evicted (data1 remains because it was accessed)
    TEST_ASSERT_NULL(cs.find(data2.name(), false, 60000));
    TEST_ASSERT_NOT_NULL(cs.find(data1.name(), false, 60000));
}

// =============================================================================
// Stats tests
// =============================================================================

void test_ContentStore_stats_initial_values(void) {
    ndn::ContentStore cs;

    TEST_ASSERT_EQUAL(0, cs.stats().hits);
    TEST_ASSERT_EQUAL(0, cs.stats().misses);
    TEST_ASSERT_EQUAL(0, cs.stats().insertions);
    TEST_ASSERT_EQUAL(0, cs.stats().evictions);
}

void test_ContentStore_stats_tracks_operations(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data;
    data.setName("/test");

    // insert
    cs.insert(data, 1000);
    TEST_ASSERT_EQUAL(1, cs.stats().insertions);

    // hit
    cs.find(data.name(), false, 1000);
    TEST_ASSERT_EQUAL(1, cs.stats().hits);

    // miss
    auto otherName = ndn::Name::fromUri("/other");
    TEST_ASSERT_TRUE(otherName.ok());
    cs.find(otherName.value, false, 1000);
    TEST_ASSERT_EQUAL(1, cs.stats().misses);
}

// =============================================================================
// Slot reuse tests
// =============================================================================

void test_ContentStore_reuses_slot_after_remove(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data1;
    data1.setName("/first");
    cs.insert(data1, 1000);

    cs.remove(data1.name());
    TEST_ASSERT_EQUAL(0, cs.size());

    ndn::Data data2;
    data2.setName("/second");
    auto err = cs.insert(data2, 2000);

    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_EQUAL(1, cs.size());
}

void test_ContentStore_reuses_slot_after_evictStale(void) {
    ndn::ContentStore cs;
    cs.init(10);

    ndn::Data data1;
    data1.setName("/stale");
    data1.setFreshnessPeriod(1000);
    cs.insert(data1, 1000);

    // Evict after stale
    cs.evictStale(3000);
    TEST_ASSERT_EQUAL(0, cs.size());

    // Insert new data
    ndn::Data data2;
    data2.setName("/new");
    auto err = cs.insert(data2, 3000);

    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
    TEST_ASSERT_EQUAL(1, cs.size());
}

// =============================================================================
// Test runner
// =============================================================================

void run_cs_tests(void) {
    // CsEntry tests
    RUN_TEST(test_CsEntry_isFresh_returns_true_when_staleTime_is_zero);
    RUN_TEST(test_CsEntry_isFresh_returns_true_when_before_staleTime);
    RUN_TEST(test_CsEntry_isFresh_returns_false_when_at_or_after_staleTime);

    // ContentStore insert tests
    RUN_TEST(test_ContentStore_insert_new_entry);
    RUN_TEST(test_ContentStore_insert_updates_existing_entry);
    RUN_TEST(test_ContentStore_insert_sets_staleTime_with_freshnessPeriod);
    RUN_TEST(test_ContentStore_insert_sets_staleTime_zero_without_freshnessPeriod);
    RUN_TEST(test_ContentStore_insert_fills_to_capacity);

    // ContentStore find tests
    RUN_TEST(test_ContentStore_find_existing_entry);
    RUN_TEST(test_ContentStore_find_nonexistent_entry);
    RUN_TEST(test_ContentStore_find_mustBeFresh_returns_fresh_entry);
    RUN_TEST(test_ContentStore_find_mustBeFresh_returns_null_for_stale_entry);
    RUN_TEST(test_ContentStore_find_mustBeFresh_false_returns_stale_entry);
    RUN_TEST(test_ContentStore_find_updates_lastUsed);

    // ContentStore remove tests
    RUN_TEST(test_ContentStore_remove_existing_entry);
    RUN_TEST(test_ContentStore_remove_nonexistent_does_nothing);

    // ContentStore evictStale tests
    RUN_TEST(test_ContentStore_evictStale_removes_stale_entries);
    RUN_TEST(test_ContentStore_evictStale_does_nothing_when_all_fresh);

    // LRU eviction tests
    RUN_TEST(test_ContentStore_lru_eviction_removes_oldest_used);
    RUN_TEST(test_ContentStore_lru_eviction_considers_find_access);

    // Stats tests
    RUN_TEST(test_ContentStore_stats_initial_values);
    RUN_TEST(test_ContentStore_stats_tracks_operations);

    // Slot reuse tests
    RUN_TEST(test_ContentStore_reuses_slot_after_remove);
    RUN_TEST(test_ContentStore_reuses_slot_after_evictStale);
}
