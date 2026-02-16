/**
 * @file test_espnow_face.cpp
 * @brief ESP-NOW Face unit tests
 *
 * Note: Since ESP-NOW only works on real hardware, this test file
 * mainly tests helper functions and data structures.
 * Actual send/receive should be verified in integration tests.
 */

#include "espnow_face.hpp"

#include <cstring>

#include "unity.h"

// =============================================================================
// macToFaceId tests
// =============================================================================

void test_macToFaceId_returns_unique_id(void) {
    uint8_t mac1[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t mac2[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x56};
    uint8_t mac3[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    ndn::FaceId id1 = ndn::macToFaceId(mac1);
    ndn::FaceId id2 = ndn::macToFaceId(mac2);
    ndn::FaceId id3 = ndn::macToFaceId(mac3);

    // Different MACs produce different IDs
    TEST_ASSERT_NOT_EQUAL(id1, id2);
    TEST_ASSERT_NOT_EQUAL(id1, id3);
    TEST_ASSERT_NOT_EQUAL(id2, id3);

    // ID is greater than 1 (avoids FACE_ID_INVALID=0, FACE_ID_LOCAL=1)
    TEST_ASSERT_GREATER_THAN(1, id1);
    TEST_ASSERT_GREATER_THAN(1, id2);
    TEST_ASSERT_GREATER_THAN(1, id3);
}

void test_macToFaceId_same_mac_returns_same_id(void) {
    uint8_t mac[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};

    ndn::FaceId id1 = ndn::macToFaceId(mac);
    ndn::FaceId id2 = ndn::macToFaceId(mac);

    TEST_ASSERT_EQUAL(id1, id2);
}

void test_macToFaceId_uses_last_two_bytes(void) {
    // Same lower 2 bytes produce same ID
    uint8_t mac1[] = {0x00, 0x00, 0x00, 0x00, 0x12, 0x34};
    uint8_t mac2[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x12, 0x34};

    ndn::FaceId id1 = ndn::macToFaceId(mac1);
    ndn::FaceId id2 = ndn::macToFaceId(mac2);

    TEST_ASSERT_EQUAL(id1, id2);
}

// =============================================================================
// PeerInfo tests
// =============================================================================

void test_PeerInfo_initialization(void) {
    ndn::PeerInfo peer = {};

    TEST_ASSERT_FALSE(peer.inUse);
    TEST_ASSERT_EQUAL(0, peer.faceId);
    TEST_ASSERT_EQUAL(0, peer.lastSeen);
}

// =============================================================================
// BROADCAST_MAC tests
// =============================================================================

void test_BROADCAST_MAC_is_all_ff(void) {
    TEST_ASSERT_EQUAL(0xFF, ndn::BROADCAST_MAC[0]);
    TEST_ASSERT_EQUAL(0xFF, ndn::BROADCAST_MAC[1]);
    TEST_ASSERT_EQUAL(0xFF, ndn::BROADCAST_MAC[2]);
    TEST_ASSERT_EQUAL(0xFF, ndn::BROADCAST_MAC[3]);
    TEST_ASSERT_EQUAL(0xFF, ndn::BROADCAST_MAC[4]);
    TEST_ASSERT_EQUAL(0xFF, ndn::BROADCAST_MAC[5]);
}

// =============================================================================
// Constants tests
// =============================================================================

void test_ESPNOW_MAX_PAYLOAD_is_1470(void) {
    // WiFi LR mode uses larger MTU (1470 bytes)
    TEST_ASSERT_EQUAL(1470, ndn::ESPNOW_MAX_PAYLOAD);
}

void test_ESPNOW_MAX_PEERS_is_20(void) {
    TEST_ASSERT_EQUAL(20, ndn::ESPNOW_MAX_PEERS);
}

// =============================================================================
// EspNowFace basic tests (without ESP-NOW initialization)
// =============================================================================

void test_EspNowFace_constructor_sets_face_id(void) {
    ndn::EspNowFace face(42);
    TEST_ASSERT_EQUAL(42, face.id());
}

void test_EspNowFace_default_face_id_is_2(void) {
    ndn::EspNowFace face;
    TEST_ASSERT_EQUAL(2, face.id());
}

void test_EspNowFace_maxPayloadSize_is_1470(void) {
    ndn::EspNowFace face;
    TEST_ASSERT_EQUAL(1470, face.maxPayloadSize());
}

void test_EspNowFace_peerCount_initially_zero(void) {
    ndn::EspNowFace face;
    TEST_ASSERT_EQUAL(0, face.peerCount());
}

void test_EspNowFace_getMacAddress_returns_false_for_unknown_peer(void) {
    ndn::EspNowFace face;
    uint8_t mac[6];

    bool result = face.getMacAddress(100, mac);
    TEST_ASSERT_FALSE(result);
}

void test_EspNowFace_send_fails_when_not_running(void) {
    ndn::EspNowFace face;
    uint8_t data[] = {0x01, 0x02, 0x03};

    ndn::Error err = face.send(data, sizeof(data));
    TEST_ASSERT_EQUAL(ndn::Error::SendFailed, err);
}

void test_EspNowFace_broadcast_fails_when_not_running(void) {
    ndn::EspNowFace face;
    uint8_t data[] = {0x01, 0x02, 0x03};

    ndn::Error err = face.broadcast(data, sizeof(data));
    TEST_ASSERT_EQUAL(ndn::Error::SendFailed, err);
}

void test_EspNowFace_sendTo_fails_when_not_running(void) {
    ndn::EspNowFace face;
    uint8_t data[] = {0x01, 0x02, 0x03};

    ndn::Error err = face.sendTo(10, data, sizeof(data));
    TEST_ASSERT_EQUAL(ndn::Error::SendFailed, err);
}

void test_EspNowFace_instance_is_null_initially(void) {
    TEST_ASSERT_NULL(ndn::EspNowFace::instance());
}

// =============================================================================
// Test runner
// =============================================================================

void run_espnow_face_tests(void) {
    // macToFaceId tests
    RUN_TEST(test_macToFaceId_returns_unique_id);
    RUN_TEST(test_macToFaceId_same_mac_returns_same_id);
    RUN_TEST(test_macToFaceId_uses_last_two_bytes);

    // PeerInfo tests
    RUN_TEST(test_PeerInfo_initialization);

    // Constants tests
    RUN_TEST(test_BROADCAST_MAC_is_all_ff);
    RUN_TEST(test_ESPNOW_MAX_PAYLOAD_is_1470);
    RUN_TEST(test_ESPNOW_MAX_PEERS_is_20);

    // EspNowFace basic tests
    RUN_TEST(test_EspNowFace_constructor_sets_face_id);
    RUN_TEST(test_EspNowFace_default_face_id_is_2);
    RUN_TEST(test_EspNowFace_maxPayloadSize_is_1470);
    RUN_TEST(test_EspNowFace_peerCount_initially_zero);
    RUN_TEST(test_EspNowFace_getMacAddress_returns_false_for_unknown_peer);
    RUN_TEST(test_EspNowFace_send_fails_when_not_running);
    RUN_TEST(test_EspNowFace_broadcast_fails_when_not_running);
    RUN_TEST(test_EspNowFace_sendTo_fails_when_not_running);
    RUN_TEST(test_EspNowFace_instance_is_null_initially);
}
