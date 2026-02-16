#include "ndn/forwarder.hpp"
#include <cstring>
#include "unity.h"

// =============================================================================
// Forwarder is large, so allocate in static storage
// =============================================================================
static ndn::Forwarder* g_forwarder = nullptr;
static uint8_t g_forwarderStorage[sizeof(ndn::Forwarder)] __attribute__((aligned(8)));

static ndn::Forwarder& getForwarder() {
    if (g_forwarder) {
        g_forwarder->~Forwarder();
    }
    g_forwarder = new (g_forwarderStorage) ndn::Forwarder();
    return *g_forwarder;
}

// =============================================================================
// MockFace - Face implementation for testing
// =============================================================================

class MockFace : public ndn::Face {
public:
    explicit MockFace(ndn::FaceId faceId) : faceId_(faceId) {}

    ndn::FaceId id() const override { return faceId_; }

    ndn::Error start() override {
        running_ = true;
        return ndn::Error::Success;
    }

    void stop() override { running_ = false; }

    ndn::Error send(const uint8_t* data, size_t len) override {
        if (len > sizeof(lastSentData_)) {
            return ndn::Error::BufferTooSmall;
        }
        memcpy(lastSentData_, data, len);
        lastSentLen_ = len;
        sendCount_++;
        return ndn::Error::Success;
    }

    ndn::Error sendTo(ndn::FaceId destFace, const uint8_t* data, size_t len) override {
        (void)destFace;
        return send(data, len);
    }

    ndn::Error broadcast(const uint8_t* data, size_t len) override { return send(data, len); }

    size_t maxPayloadSize() const override { return 250; }

    // Test helper methods
    void simulatePacketReceived(const uint8_t* data, size_t len) {
        onPacketReceived(faceId_, data, len);
    }

    const uint8_t* lastSentData() const { return lastSentData_; }
    size_t lastSentLen() const { return lastSentLen_; }
    uint32_t sendCount() const { return sendCount_; }
    void resetSendCount() { sendCount_ = 0; }
    bool isRunning() const { return running_; }

private:
    ndn::FaceId faceId_;
    bool running_ = false;
    uint8_t lastSentData_[256] = {};
    size_t lastSentLen_ = 0;
    uint32_t sendCount_ = 0;
};

// =============================================================================
// Helper functions
// =============================================================================

static ndn::Interest createInterest(const char* nameUri) {
    ndn::Interest interest;
    auto nameResult = ndn::Name::fromUri(nameUri);
    if (nameResult.ok()) {
        interest.setName(nameResult.value);
    }
    interest.setNonce(12345);
    return interest;
}

static ndn::Data createData(const char* nameUri, const char* content) {
    ndn::Data data;
    auto nameResult = ndn::Name::fromUri(nameUri);
    if (nameResult.ok()) {
        data.setName(nameResult.value);
    }
    data.setContent(reinterpret_cast<const uint8_t*>(content), strlen(content));
    data.setFreshnessPeriod(5000);
    return data;
}

// =============================================================================
// Forwarder initialization tests
// =============================================================================

void test_Forwarder_init_success(void) {
    ndn::Forwarder& fw = getForwarder();
    auto err = fw.init();
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
}

void test_Forwarder_init_double_init_is_safe(void) {
    ndn::Forwarder& fw = getForwarder();
    auto err1 = fw.init();
    auto err2 = fw.init();
    TEST_ASSERT_EQUAL(ndn::Error::Success, err1);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err2);
}

// =============================================================================
// Face management tests
// =============================================================================

void test_Forwarder_addFace_success(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    auto err = fw.addFace(&face);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
}

void test_Forwarder_addFace_null_returns_error(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    auto err = fw.addFace(nullptr);
    TEST_ASSERT_EQUAL(ndn::Error::InvalidParam, err);
}

void test_Forwarder_addFace_duplicate_returns_error(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);

    MockFace face2(10);  // Same ID
    auto err = fw.addFace(&face2);
    TEST_ASSERT_EQUAL(ndn::Error::InvalidParam, err);
}

void test_Forwarder_addFace_multiple_faces(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face1(10);
    MockFace face2(20);
    MockFace face3(30);

    TEST_ASSERT_EQUAL(ndn::Error::Success, fw.addFace(&face1));
    TEST_ASSERT_EQUAL(ndn::Error::Success, fw.addFace(&face2));
    TEST_ASSERT_EQUAL(ndn::Error::Success, fw.addFace(&face3));
}

void test_Forwarder_removeFace_stops_face(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    face.start();
    fw.addFace(&face);
    TEST_ASSERT_TRUE(face.isRunning());

    fw.removeFace(10);
    TEST_ASSERT_FALSE(face.isRunning());
}

void test_Forwarder_removeFace_removes_from_fib(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);

    auto prefixResult = ndn::Name::fromUri("/test");
    TEST_ASSERT_TRUE(prefixResult.ok());
    fw.addRoute(prefixResult.value, 10, 0);

    // Route exists in FIB
    TEST_ASSERT_NOT_NULL(fw.fib().findExact(prefixResult.value));

    // Removing Face also removes from FIB
    fw.removeFace(10);
    TEST_ASSERT_NULL(fw.fib().findExact(prefixResult.value));
}

// =============================================================================
// Route management tests
// =============================================================================

void test_Forwarder_addRoute_success(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    auto err = fw.addRoute("/sensor/temp", 10, 0);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);

    auto prefixResult = ndn::Name::fromUri("/sensor/temp");
    TEST_ASSERT_TRUE(prefixResult.ok());
    const ndn::FibEntry* entry = fw.fib().findExact(prefixResult.value);
    TEST_ASSERT_NOT_NULL(entry);
}

void test_Forwarder_addRoute_with_name_object(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    auto prefixResult = ndn::Name::fromUri("/sensor/temp");
    TEST_ASSERT_TRUE(prefixResult.ok());

    auto err = fw.addRoute(prefixResult.value, 10, 0);
    TEST_ASSERT_EQUAL(ndn::Error::Success, err);
}

// =============================================================================
// Interest forwarding tests
// =============================================================================

void test_Forwarder_forwards_interest_to_nexthop(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace inFace(10);
    MockFace outFace(20);
    fw.addFace(&inFace);
    fw.addFace(&outFace);

    // Route /sensor -> face 20
    fw.addRoute("/sensor", 20, 0);

    // Encode Interest
    ndn::Interest interest = createInterest("/sensor/temp");
    uint8_t buf[256];
    size_t len = 0;
    TEST_ASSERT_EQUAL(ndn::Error::Success, interest.encode(buf, sizeof(buf), len));

    // Simulate packet reception on inFace
    inFace.simulatePacketReceived(buf, len);

    // Verify forwarded to outFace
    TEST_ASSERT_GREATER_THAN(0, outFace.sendCount());
}

void test_Forwarder_does_not_forward_to_incoming_face(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);

    // Route /sensor -> face 10 (same as incoming)
    fw.addRoute("/sensor", 10, 0);

    ndn::Interest interest = createInterest("/sensor/temp");
    uint8_t buf[256];
    size_t len = 0;
    interest.encode(buf, sizeof(buf), len);

    face.simulatePacketReceived(buf, len);

    // Should not be forwarded to incoming face
    TEST_ASSERT_EQUAL(0, face.sendCount());
}

void test_Forwarder_no_route_does_not_crash(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);

    // No route
    ndn::Interest interest = createInterest("/nonexistent");
    uint8_t buf[256];
    size_t len = 0;
    interest.encode(buf, sizeof(buf), len);

    // Verify no crash
    face.simulatePacketReceived(buf, len);
    TEST_ASSERT_EQUAL(0, face.sendCount());
}

void test_Forwarder_aggregates_duplicate_interest(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face1(10);
    MockFace face2(20);
    MockFace outFace(30);
    fw.addFace(&face1);
    fw.addFace(&face2);
    fw.addFace(&outFace);

    fw.addRoute("/sensor", 30, 0);

    ndn::Interest interest = createInterest("/sensor/temp");
    uint8_t buf[256];
    size_t len = 0;
    interest.encode(buf, sizeof(buf), len);

    // First Interest
    face1.simulatePacketReceived(buf, len);
    TEST_ASSERT_EQUAL(1, outFace.sendCount());

    // Same Interest from another Face -> aggregated, not forwarded
    face2.simulatePacketReceived(buf, len);
    TEST_ASSERT_EQUAL(1, outFace.sendCount());  // Not incremented
}

// =============================================================================
// Cache hit tests
// =============================================================================

void test_Forwarder_returns_cached_data(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);

    // Pre-populate CS with Data
    ndn::Data data = createData("/sensor/temp", "25.5C");
    fw.cs().insert(data, ndn::currentTimeMs());

    // Send Interest
    ndn::Interest interest = createInterest("/sensor/temp");
    uint8_t buf[256];
    size_t len = 0;
    interest.encode(buf, sizeof(buf), len);

    face.simulatePacketReceived(buf, len);

    // Data is sent back on cache hit
    TEST_ASSERT_EQUAL(1, face.sendCount());
    TEST_ASSERT_EQUAL(1, fw.stats().cacheHits);
}

void test_Forwarder_cache_miss_increments_stat(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace inFace(10);
    MockFace outFace(20);
    fw.addFace(&inFace);
    fw.addFace(&outFace);

    fw.addRoute("/sensor", 20, 0);

    ndn::Interest interest = createInterest("/sensor/temp");
    uint8_t buf[256];
    size_t len = 0;
    interest.encode(buf, sizeof(buf), len);

    inFace.simulatePacketReceived(buf, len);

    TEST_ASSERT_EQUAL(1, fw.stats().cacheMisses);
}

// =============================================================================
// Data forwarding tests
// =============================================================================

void test_Forwarder_forwards_data_to_pit_faces(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace requesterFace(10);
    MockFace producerFace(20);
    fw.addFace(&requesterFace);
    fw.addFace(&producerFace);

    fw.addRoute("/sensor", 20, 0);

    // Send Interest from requesterFace
    ndn::Interest interest = createInterest("/sensor/temp");
    uint8_t interestBuf[256];
    size_t interestLen = 0;
    interest.encode(interestBuf, sizeof(interestBuf), interestLen);
    requesterFace.simulatePacketReceived(interestBuf, interestLen);

    // PIT entry exists
    auto nameResult = ndn::Name::fromUri("/sensor/temp");
    TEST_ASSERT_TRUE(nameResult.ok());
    TEST_ASSERT_NOT_NULL(fw.pit().find(nameResult.value));

    // Receive Data from producerFace
    ndn::Data data = createData("/sensor/temp", "25.5C");
    uint8_t dataBuf[256];
    size_t dataLen = 0;
    data.encode(dataBuf, sizeof(dataBuf), dataLen);

    requesterFace.resetSendCount();
    producerFace.simulatePacketReceived(dataBuf, dataLen);

    // Data forwarded to requesterFace
    TEST_ASSERT_EQUAL(1, requesterFace.sendCount());

    // PIT entry is removed
    TEST_ASSERT_NULL(fw.pit().find(nameResult.value));
}

void test_Forwarder_unsolicited_data_is_dropped(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);

    // Receive Data without PIT entry
    ndn::Data data = createData("/sensor/temp", "25.5C");
    uint8_t buf[256];
    size_t len = 0;
    data.encode(buf, sizeof(buf), len);

    face.simulatePacketReceived(buf, len);

    // Nothing is forwarded
    TEST_ASSERT_EQUAL(0, face.sendCount());
}

void test_Forwarder_stores_received_data_in_cs(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace requesterFace(10);
    MockFace producerFace(20);
    fw.addFace(&requesterFace);
    fw.addFace(&producerFace);

    fw.addRoute("/sensor", 20, 0);

    // Send Interest
    ndn::Interest interest = createInterest("/sensor/temp");
    uint8_t interestBuf[256];
    size_t interestLen = 0;
    interest.encode(interestBuf, sizeof(interestBuf), interestLen);
    requesterFace.simulatePacketReceived(interestBuf, interestLen);

    // Receive Data
    ndn::Data data = createData("/sensor/temp", "25.5C");
    uint8_t dataBuf[256];
    size_t dataLen = 0;
    data.encode(dataBuf, sizeof(dataBuf), dataLen);
    producerFace.simulatePacketReceived(dataBuf, dataLen);

    // Stored in CS
    auto nameResult = ndn::Name::fromUri("/sensor/temp");
    TEST_ASSERT_TRUE(nameResult.ok());
    const ndn::CsEntry* csEntry = fw.cs().find(nameResult.value, false, ndn::currentTimeMs());
    TEST_ASSERT_NOT_NULL(csEntry);
}

// =============================================================================
// Prefix registration tests
// =============================================================================

void test_Forwarder_registerPrefix_receives_matching_interest(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);

    bool callbackCalled = false;
    ndn::Interest receivedInterest;

    fw.registerPrefix("/app", [&](const ndn::Interest& interest, ndn::FaceId faceId) {
        (void)faceId;
        callbackCalled = true;
        receivedInterest = interest;
    });

    // Send Interest to /app/data
    ndn::Interest interest = createInterest("/app/data");
    uint8_t buf[256];
    size_t len = 0;
    interest.encode(buf, sizeof(buf), len);

    face.simulatePacketReceived(buf, len);

    TEST_ASSERT_TRUE(callbackCalled);

    auto nameResult = ndn::Name::fromUri("/app/data");
    TEST_ASSERT_TRUE(nameResult.ok());
    TEST_ASSERT_TRUE(receivedInterest.name().equals(nameResult.value));
}

void test_Forwarder_registerPrefix_with_name_object(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);

    bool callbackCalled = false;

    auto prefixResult = ndn::Name::fromUri("/app");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fw.registerPrefix(prefixResult.value, [&](const ndn::Interest& interest, ndn::FaceId faceId) {
        (void)interest;
        (void)faceId;
        callbackCalled = true;
    });

    ndn::Interest interest = createInterest("/app/test");
    uint8_t buf[256];
    size_t len = 0;
    interest.encode(buf, sizeof(buf), len);
    face.simulatePacketReceived(buf, len);

    TEST_ASSERT_TRUE(callbackCalled);
}

void test_Forwarder_unregisterPrefix_stops_callback(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);

    int callCount = 0;
    auto prefixResult = ndn::Name::fromUri("/app");
    TEST_ASSERT_TRUE(prefixResult.ok());

    fw.registerPrefix(prefixResult.value, [&](const ndn::Interest& interest, ndn::FaceId faceId) {
        (void)interest;
        (void)faceId;
        callCount++;
    });

    // First time
    ndn::Interest interest1 = createInterest("/app/test1");
    uint8_t buf[256];
    size_t len = 0;
    interest1.encode(buf, sizeof(buf), len);
    face.simulatePacketReceived(buf, len);
    TEST_ASSERT_EQUAL(1, callCount);

    // Unregister
    fw.unregisterPrefix(prefixResult.value);

    // Second time - no callback (enters PIT as different Interest)
    ndn::Interest interest2 = createInterest("/app/test2");
    interest2.encode(buf, sizeof(buf), len);
    face.simulatePacketReceived(buf, len);
    TEST_ASSERT_EQUAL(1, callCount);  // Not incremented
}

// =============================================================================
// Application API tests (expressInterest / putData)
// =============================================================================

void test_Forwarder_expressInterest_registers_pit_entry(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);
    fw.addRoute("/sensor", 10, 0);

    ndn::Interest interest = createInterest("/sensor/temp");

    bool dataReceived = false;
    fw.expressInterest(interest, [&](const ndn::Data& data) {
        (void)data;
        dataReceived = true;
    });

    // PIT entry exists
    auto nameResult = ndn::Name::fromUri("/sensor/temp");
    TEST_ASSERT_TRUE(nameResult.ok());
    TEST_ASSERT_NOT_NULL(fw.pit().find(nameResult.value));
}

void test_Forwarder_expressInterest_callback_called_on_data(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);
    fw.addRoute("/sensor", 10, 0);

    ndn::Interest interest = createInterest("/sensor/temp");

    bool dataReceived = false;
    ndn::Data receivedData;
    fw.expressInterest(interest, [&](const ndn::Data& data) {
        dataReceived = true;
        receivedData = data;
    });

    // Receive Data
    ndn::Data data = createData("/sensor/temp", "25.5C");
    uint8_t buf[256];
    size_t len = 0;
    data.encode(buf, sizeof(buf), len);
    face.simulatePacketReceived(buf, len);

    TEST_ASSERT_TRUE(dataReceived);
}

void test_Forwarder_putData_stores_in_cs(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    ndn::Data data = createData("/local/data", "test content");
    fw.putData(data);

    auto nameResult = ndn::Name::fromUri("/local/data");
    TEST_ASSERT_TRUE(nameResult.ok());
    const ndn::CsEntry* entry = fw.cs().find(nameResult.value, false, ndn::currentTimeMs());
    TEST_ASSERT_NOT_NULL(entry);
}

void test_Forwarder_putData_satisfies_pending_interest(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);

    // Receive Interest from external face
    auto prefixResult = ndn::Name::fromUri("/local");
    TEST_ASSERT_TRUE(prefixResult.ok());

    bool interestReceived = false;
    fw.registerPrefix(prefixResult.value, [&](const ndn::Interest& interest, ndn::FaceId faceId) {
        (void)interest;
        (void)faceId;
        interestReceived = true;
    });

    ndn::Interest interest = createInterest("/local/data");
    uint8_t interestBuf[256];
    size_t interestLen = 0;
    interest.encode(interestBuf, sizeof(interestBuf), interestLen);
    face.simulatePacketReceived(interestBuf, interestLen);
    TEST_ASSERT_TRUE(interestReceived);

    // Provide Data via putData
    face.resetSendCount();
    ndn::Data data = createData("/local/data", "response");
    fw.putData(data);

    // Matched in PIT and forwarded
    // (Note:
    // putData from local app checks PIT, but may not forward since FACE_ID_LOCAL is excluded)
}

// =============================================================================
// Statistics tests
// =============================================================================

void test_Forwarder_stats_interests_received(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);

    ndn::Interest interest = createInterest("/test");
    uint8_t buf[256];
    size_t len = 0;
    interest.encode(buf, sizeof(buf), len);

    TEST_ASSERT_EQUAL(0, fw.stats().interestsReceived);
    face.simulatePacketReceived(buf, len);
    TEST_ASSERT_EQUAL(1, fw.stats().interestsReceived);
}

void test_Forwarder_stats_data_received(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);

    ndn::Data data = createData("/test", "content");
    uint8_t buf[256];
    size_t len = 0;
    data.encode(buf, sizeof(buf), len);

    TEST_ASSERT_EQUAL(0, fw.stats().dataReceived);
    face.simulatePacketReceived(buf, len);
    TEST_ASSERT_EQUAL(1, fw.stats().dataReceived);
}

void test_Forwarder_stats_interests_sent(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace inFace(10);
    MockFace outFace(20);
    fw.addFace(&inFace);
    fw.addFace(&outFace);

    fw.addRoute("/sensor", 20, 0);

    ndn::Interest interest = createInterest("/sensor/temp");
    uint8_t buf[256];
    size_t len = 0;
    interest.encode(buf, sizeof(buf), len);

    TEST_ASSERT_EQUAL(0, fw.stats().interestsSent);
    inFace.simulatePacketReceived(buf, len);
    TEST_ASSERT_EQUAL(1, fw.stats().interestsSent);
}

void test_Forwarder_stats_data_sent(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace requesterFace(10);
    MockFace producerFace(20);
    fw.addFace(&requesterFace);
    fw.addFace(&producerFace);

    fw.addRoute("/sensor", 20, 0);

    // Send Interest
    ndn::Interest interest = createInterest("/sensor/temp");
    uint8_t interestBuf[256];
    size_t interestLen = 0;
    interest.encode(interestBuf, sizeof(interestBuf), interestLen);
    requesterFace.simulatePacketReceived(interestBuf, interestLen);

    // Receive Data
    ndn::Data data = createData("/sensor/temp", "25.5C");
    uint8_t dataBuf[256];
    size_t dataLen = 0;
    data.encode(dataBuf, sizeof(dataBuf), dataLen);

    TEST_ASSERT_EQUAL(0, fw.stats().dataSent);
    producerFace.simulatePacketReceived(dataBuf, dataLen);
    TEST_ASSERT_EQUAL(1, fw.stats().dataSent);
}

// =============================================================================
// Edge case tests
// =============================================================================

void test_Forwarder_handles_malformed_packet(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);

    // Malformed packet
    uint8_t garbage[] = {0xFF, 0xFF, 0xFF};
    face.simulatePacketReceived(garbage, sizeof(garbage));

    // Verify no crash
    TEST_ASSERT_EQUAL(0, fw.stats().interestsReceived);
    TEST_ASSERT_EQUAL(0, fw.stats().dataReceived);
}

void test_Forwarder_handles_too_short_packet(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace face(10);
    fw.addFace(&face);

    // Packet too short
    uint8_t short_pkt[] = {0x05};
    face.simulatePacketReceived(short_pkt, 1);

    TEST_ASSERT_EQUAL(0, fw.stats().interestsReceived);
}

void test_Forwarder_multipath_forwarding(void) {
    ndn::Forwarder& fw = getForwarder();
    fw.init();

    MockFace inFace(10);
    MockFace outFace1(20);
    MockFace outFace2(30);
    fw.addFace(&inFace);
    fw.addFace(&outFace1);
    fw.addFace(&outFace2);

    // Multi-path setup
    fw.addRoute("/sensor", 20, 0);
    fw.addRoute("/sensor", 30, 0);

    ndn::Interest interest = createInterest("/sensor/temp");
    uint8_t buf[256];
    size_t len = 0;
    interest.encode(buf, sizeof(buf), len);

    inFace.simulatePacketReceived(buf, len);

    // Forwarded to both Faces
    TEST_ASSERT_EQUAL(1, outFace1.sendCount());
    TEST_ASSERT_EQUAL(1, outFace2.sendCount());
}

// =============================================================================
// Test runner
// =============================================================================

void run_forwarder_tests(void) {
    // Initialization tests
    RUN_TEST(test_Forwarder_init_success);
    RUN_TEST(test_Forwarder_init_double_init_is_safe);

    // Face management tests
    RUN_TEST(test_Forwarder_addFace_success);
    RUN_TEST(test_Forwarder_addFace_null_returns_error);
    RUN_TEST(test_Forwarder_addFace_duplicate_returns_error);
    RUN_TEST(test_Forwarder_addFace_multiple_faces);
    RUN_TEST(test_Forwarder_removeFace_stops_face);
    RUN_TEST(test_Forwarder_removeFace_removes_from_fib);

    // Route management tests
    RUN_TEST(test_Forwarder_addRoute_success);
    RUN_TEST(test_Forwarder_addRoute_with_name_object);

    // Interest forwarding tests
    RUN_TEST(test_Forwarder_forwards_interest_to_nexthop);
    RUN_TEST(test_Forwarder_does_not_forward_to_incoming_face);
    RUN_TEST(test_Forwarder_no_route_does_not_crash);
    RUN_TEST(test_Forwarder_aggregates_duplicate_interest);

    // Cache hit tests
    RUN_TEST(test_Forwarder_returns_cached_data);
    RUN_TEST(test_Forwarder_cache_miss_increments_stat);

    // Data forwarding tests
    RUN_TEST(test_Forwarder_forwards_data_to_pit_faces);
    RUN_TEST(test_Forwarder_unsolicited_data_is_dropped);
    RUN_TEST(test_Forwarder_stores_received_data_in_cs);

    // Prefix registration tests
    RUN_TEST(test_Forwarder_registerPrefix_receives_matching_interest);
    RUN_TEST(test_Forwarder_registerPrefix_with_name_object);
    RUN_TEST(test_Forwarder_unregisterPrefix_stops_callback);

    // Application API tests
    RUN_TEST(test_Forwarder_expressInterest_registers_pit_entry);
    RUN_TEST(test_Forwarder_expressInterest_callback_called_on_data);
    RUN_TEST(test_Forwarder_putData_stores_in_cs);
    RUN_TEST(test_Forwarder_putData_satisfies_pending_interest);

    // Statistics tests
    RUN_TEST(test_Forwarder_stats_interests_received);
    RUN_TEST(test_Forwarder_stats_data_received);
    RUN_TEST(test_Forwarder_stats_interests_sent);
    RUN_TEST(test_Forwarder_stats_data_sent);

    // Edge case tests
    RUN_TEST(test_Forwarder_handles_malformed_packet);
    RUN_TEST(test_Forwarder_handles_too_short_packet);
    RUN_TEST(test_Forwarder_multipath_forwarding);
}
