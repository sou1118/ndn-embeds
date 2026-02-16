#include "ndn/tlv.hpp"
#include "unity.h"

// =============================================================================
// varNumberSize / nonNegativeIntegerSize
// =============================================================================

void test_varNumberSize_calculates_correct_sizes(void) {
    // 1-byte range (0-252)
    TEST_ASSERT_EQUAL(1, ndn::varNumberSize(0));
    TEST_ASSERT_EQUAL(1, ndn::varNumberSize(1));
    TEST_ASSERT_EQUAL(1, ndn::varNumberSize(252));

    // 3-byte range (253-65535)
    TEST_ASSERT_EQUAL(3, ndn::varNumberSize(253));
    TEST_ASSERT_EQUAL(3, ndn::varNumberSize(1000));
    TEST_ASSERT_EQUAL(3, ndn::varNumberSize(65535));

    // 5-byte range (65536-4294967295)
    TEST_ASSERT_EQUAL(5, ndn::varNumberSize(65536));
    TEST_ASSERT_EQUAL(5, ndn::varNumberSize(0xFFFFFFFF));

    // 9-byte range
    TEST_ASSERT_EQUAL(9, ndn::varNumberSize(0x100000000ULL));
}

void test_nonNegativeIntegerSize_calculates_correct_sizes(void) {
    // 1 byte (0-255)
    TEST_ASSERT_EQUAL(1, ndn::nonNegativeIntegerSize(0));
    TEST_ASSERT_EQUAL(1, ndn::nonNegativeIntegerSize(255));

    // 2 bytes (256-65535)
    TEST_ASSERT_EQUAL(2, ndn::nonNegativeIntegerSize(256));
    TEST_ASSERT_EQUAL(2, ndn::nonNegativeIntegerSize(65535));

    // 4 bytes (65536-4294967295)
    TEST_ASSERT_EQUAL(4, ndn::nonNegativeIntegerSize(65536));
    TEST_ASSERT_EQUAL(4, ndn::nonNegativeIntegerSize(0xFFFFFFFF));

    // 8 bytes
    TEST_ASSERT_EQUAL(8, ndn::nonNegativeIntegerSize(0x100000000ULL));
}

// =============================================================================
// TlvEncoder
// =============================================================================

void test_TlvEncoder_writes_1_byte_VarNumber(void) {
    uint8_t buf[16];
    ndn::TlvEncoder encoder(buf, sizeof(buf));

    TEST_ASSERT_EQUAL(ndn::Error::Success, encoder.writeVarNumber(0));
    TEST_ASSERT_EQUAL(ndn::Error::Success, encoder.writeVarNumber(100));
    TEST_ASSERT_EQUAL(ndn::Error::Success, encoder.writeVarNumber(252));

    TEST_ASSERT_EQUAL(3, encoder.size());
    TEST_ASSERT_EQUAL(0, buf[0]);
    TEST_ASSERT_EQUAL(100, buf[1]);
    TEST_ASSERT_EQUAL(252, buf[2]);
}

void test_TlvEncoder_writes_3_byte_VarNumber(void) {
    uint8_t buf[16];
    ndn::TlvEncoder encoder(buf, sizeof(buf));

    TEST_ASSERT_EQUAL(ndn::Error::Success, encoder.writeVarNumber(253));
    TEST_ASSERT_EQUAL(3, encoder.size());
    TEST_ASSERT_EQUAL(253, buf[0]);
    TEST_ASSERT_EQUAL(0, buf[1]);
    TEST_ASSERT_EQUAL(253, buf[2]);

    encoder.setPosition(0);
    TEST_ASSERT_EQUAL(ndn::Error::Success, encoder.writeVarNumber(0x1234));
    TEST_ASSERT_EQUAL(253, buf[0]);
    TEST_ASSERT_EQUAL(0x12, buf[1]);
    TEST_ASSERT_EQUAL(0x34, buf[2]);
}

void test_TlvEncoder_writes_5_byte_VarNumber(void) {
    uint8_t buf[16];
    ndn::TlvEncoder encoder(buf, sizeof(buf));

    TEST_ASSERT_EQUAL(ndn::Error::Success, encoder.writeVarNumber(0x12345678));
    TEST_ASSERT_EQUAL(5, encoder.size());
    TEST_ASSERT_EQUAL(254, buf[0]);
    TEST_ASSERT_EQUAL(0x12, buf[1]);
    TEST_ASSERT_EQUAL(0x34, buf[2]);
    TEST_ASSERT_EQUAL(0x56, buf[3]);
    TEST_ASSERT_EQUAL(0x78, buf[4]);
}

void test_TlvEncoder_writeNonNegativeInteger(void) {
    uint8_t buf[16];

    // 1 byte
    {
        ndn::TlvEncoder encoder(buf, sizeof(buf));
        TEST_ASSERT_EQUAL(ndn::Error::Success, encoder.writeNonNegativeInteger(0x42));
        TEST_ASSERT_EQUAL(1, encoder.size());
        TEST_ASSERT_EQUAL(0x42, buf[0]);
    }

    // 2 bytes
    {
        ndn::TlvEncoder encoder(buf, sizeof(buf));
        TEST_ASSERT_EQUAL(ndn::Error::Success, encoder.writeNonNegativeInteger(0x1234));
        TEST_ASSERT_EQUAL(2, encoder.size());
        TEST_ASSERT_EQUAL(0x12, buf[0]);
        TEST_ASSERT_EQUAL(0x34, buf[1]);
    }

    // 4 bytes
    {
        ndn::TlvEncoder encoder(buf, sizeof(buf));
        TEST_ASSERT_EQUAL(ndn::Error::Success, encoder.writeNonNegativeInteger(0x12345678));
        TEST_ASSERT_EQUAL(4, encoder.size());
        TEST_ASSERT_EQUAL(0x12, buf[0]);
        TEST_ASSERT_EQUAL(0x34, buf[1]);
        TEST_ASSERT_EQUAL(0x56, buf[2]);
        TEST_ASSERT_EQUAL(0x78, buf[3]);
    }
}

void test_TlvEncoder_writeTlv(void) {
    uint8_t buf[32];
    ndn::TlvEncoder encoder(buf, sizeof(buf));

    const uint8_t data[] = {0x01, 0x02, 0x03};
    TEST_ASSERT_EQUAL(ndn::Error::Success, encoder.writeTlv(0x08, data, 3));

    // Type=0x08, Length=3, Value={0x01, 0x02, 0x03}
    TEST_ASSERT_EQUAL(5, encoder.size());
    TEST_ASSERT_EQUAL(0x08, buf[0]);
    TEST_ASSERT_EQUAL(3, buf[1]);
    TEST_ASSERT_EQUAL(0x01, buf[2]);
    TEST_ASSERT_EQUAL(0x02, buf[3]);
    TEST_ASSERT_EQUAL(0x03, buf[4]);
}

void test_TlvEncoder_fails_on_buffer_too_small(void) {
    uint8_t buf[2];
    ndn::TlvEncoder encoder(buf, sizeof(buf));

    TEST_ASSERT_EQUAL(ndn::Error::BufferTooSmall, encoder.writeVarNumber(0x1234));
}

// =============================================================================
// TlvDecoder
// =============================================================================

void test_TlvDecoder_reads_1_byte_VarNumber(void) {
    const uint8_t data[] = {0, 100, 252};
    ndn::TlvDecoder decoder(data, sizeof(data));

    auto r1 = decoder.readVarNumber();
    TEST_ASSERT_TRUE(r1.ok());
    TEST_ASSERT_EQUAL(0, r1.value);

    auto r2 = decoder.readVarNumber();
    TEST_ASSERT_TRUE(r2.ok());
    TEST_ASSERT_EQUAL(100, r2.value);

    auto r3 = decoder.readVarNumber();
    TEST_ASSERT_TRUE(r3.ok());
    TEST_ASSERT_EQUAL(252, r3.value);
}

void test_TlvDecoder_reads_3_byte_VarNumber(void) {
    const uint8_t data[] = {253, 0x12, 0x34};
    ndn::TlvDecoder decoder(data, sizeof(data));

    auto r = decoder.readVarNumber();
    TEST_ASSERT_TRUE(r.ok());
    TEST_ASSERT_EQUAL(0x1234, r.value);
}

void test_TlvDecoder_reads_5_byte_VarNumber(void) {
    const uint8_t data[] = {254, 0x12, 0x34, 0x56, 0x78};
    ndn::TlvDecoder decoder(data, sizeof(data));

    auto r = decoder.readVarNumber();
    TEST_ASSERT_TRUE(r.ok());
    TEST_ASSERT_EQUAL(0x12345678, r.value);
}

void test_TlvDecoder_readNonNegativeInteger(void) {
    // 2 bytes
    {
        const uint8_t data[] = {0x12, 0x34};
        ndn::TlvDecoder decoder(data, sizeof(data));
        auto r = decoder.readNonNegativeInteger(2);
        TEST_ASSERT_TRUE(r.ok());
        TEST_ASSERT_EQUAL(0x1234, r.value);
    }

    // 4 bytes
    {
        const uint8_t data[] = {0x12, 0x34, 0x56, 0x78};
        ndn::TlvDecoder decoder(data, sizeof(data));
        auto r = decoder.readNonNegativeInteger(4);
        TEST_ASSERT_TRUE(r.ok());
        TEST_ASSERT_EQUAL(0x12345678, r.value);
    }
}

void test_TlvDecoder_readTlvHeader(void) {
    const uint8_t data[] = {0x08, 0x05, 'h', 'e', 'l', 'l', 'o'};
    ndn::TlvDecoder decoder(data, sizeof(data));

    auto r = decoder.readTlvHeader();
    TEST_ASSERT_TRUE(r.ok());
    TEST_ASSERT_EQUAL(0x08, r.value.type);
    TEST_ASSERT_EQUAL(5, r.value.length);
    TEST_ASSERT_EQUAL(5, decoder.remaining());
}

void test_TlvDecoder_fails_on_truncated_data(void) {
    // 3-byte VarNumber but only 2 bytes available
    const uint8_t data[] = {253, 0x12};
    ndn::TlvDecoder decoder(data, sizeof(data));

    auto r = decoder.readVarNumber();
    TEST_ASSERT_FALSE(r.ok());
    TEST_ASSERT_EQUAL(ndn::Error::DecodeFailed, r.error);
}

// =============================================================================
// Encode/Decode roundtrip
// =============================================================================

void test_TLV_encode_decode_roundtrip(void) {
    uint8_t buf[32];
    ndn::TlvEncoder encoder(buf, sizeof(buf));

    // Encode
    const uint64_t testValues[] = {0, 100, 252, 253, 1000, 65535, 65536, 0x12345678};
    for (auto v : testValues) {
        TEST_ASSERT_EQUAL(ndn::Error::Success, encoder.writeVarNumber(v));
    }

    // Decode
    ndn::TlvDecoder decoder(buf, encoder.size());
    for (auto expected : testValues) {
        auto r = decoder.readVarNumber();
        TEST_ASSERT_TRUE(r.ok());
        TEST_ASSERT_EQUAL(expected, r.value);
    }
}

// =============================================================================
// Test runner
// =============================================================================

void run_tlv_tests(void) {
    RUN_TEST(test_varNumberSize_calculates_correct_sizes);
    RUN_TEST(test_nonNegativeIntegerSize_calculates_correct_sizes);
    RUN_TEST(test_TlvEncoder_writes_1_byte_VarNumber);
    RUN_TEST(test_TlvEncoder_writes_3_byte_VarNumber);
    RUN_TEST(test_TlvEncoder_writes_5_byte_VarNumber);
    RUN_TEST(test_TlvEncoder_writeNonNegativeInteger);
    RUN_TEST(test_TlvEncoder_writeTlv);
    RUN_TEST(test_TlvEncoder_fails_on_buffer_too_small);
    RUN_TEST(test_TlvDecoder_reads_1_byte_VarNumber);
    RUN_TEST(test_TlvDecoder_reads_3_byte_VarNumber);
    RUN_TEST(test_TlvDecoder_reads_5_byte_VarNumber);
    RUN_TEST(test_TlvDecoder_readNonNegativeInteger);
    RUN_TEST(test_TlvDecoder_readTlvHeader);
    RUN_TEST(test_TlvDecoder_fails_on_truncated_data);
    RUN_TEST(test_TLV_encode_decode_roundtrip);
}
