#include "ndn/tlv.hpp"
#include <cstring>

namespace ndn {

// =============================================================================
// TlvEncoder
// =============================================================================

TlvEncoder::TlvEncoder(uint8_t* buf, size_t capacity) : buf_(buf), capacity_(capacity) {}

Error TlvEncoder::writeVarNumber(uint64_t value) {
    if (value <= 252) {
        if (remaining() < 1) {
            return Error::BufferTooSmall;
        }
        buf_[pos_++] = static_cast<uint8_t>(value);
    } else if (value <= 0xFFFF) {
        if (remaining() < 3) {
            return Error::BufferTooSmall;
        }
        buf_[pos_++] = 253;
        buf_[pos_++] = static_cast<uint8_t>(value >> 8);
        buf_[pos_++] = static_cast<uint8_t>(value);
    } else if (value <= 0xFFFFFFFF) {
        if (remaining() < 5) {
            return Error::BufferTooSmall;
        }
        buf_[pos_++] = 254;
        buf_[pos_++] = static_cast<uint8_t>(value >> 24);
        buf_[pos_++] = static_cast<uint8_t>(value >> 16);
        buf_[pos_++] = static_cast<uint8_t>(value >> 8);
        buf_[pos_++] = static_cast<uint8_t>(value);
    } else {
        if (remaining() < 9) {
            return Error::BufferTooSmall;
        }
        buf_[pos_++] = 255;
        buf_[pos_++] = static_cast<uint8_t>(value >> 56);
        buf_[pos_++] = static_cast<uint8_t>(value >> 48);
        buf_[pos_++] = static_cast<uint8_t>(value >> 40);
        buf_[pos_++] = static_cast<uint8_t>(value >> 32);
        buf_[pos_++] = static_cast<uint8_t>(value >> 24);
        buf_[pos_++] = static_cast<uint8_t>(value >> 16);
        buf_[pos_++] = static_cast<uint8_t>(value >> 8);
        buf_[pos_++] = static_cast<uint8_t>(value);
    }
    return Error::Success;
}

Error TlvEncoder::writeNonNegativeInteger(uint64_t value) {
    if (value <= 0xFF) {
        if (remaining() < 1) {
            return Error::BufferTooSmall;
        }
        buf_[pos_++] = static_cast<uint8_t>(value);
    } else if (value <= 0xFFFF) {
        if (remaining() < 2) {
            return Error::BufferTooSmall;
        }
        buf_[pos_++] = static_cast<uint8_t>(value >> 8);
        buf_[pos_++] = static_cast<uint8_t>(value);
    } else if (value <= 0xFFFFFFFF) {
        if (remaining() < 4) {
            return Error::BufferTooSmall;
        }
        buf_[pos_++] = static_cast<uint8_t>(value >> 24);
        buf_[pos_++] = static_cast<uint8_t>(value >> 16);
        buf_[pos_++] = static_cast<uint8_t>(value >> 8);
        buf_[pos_++] = static_cast<uint8_t>(value);
    } else {
        if (remaining() < 8) {
            return Error::BufferTooSmall;
        }
        buf_[pos_++] = static_cast<uint8_t>(value >> 56);
        buf_[pos_++] = static_cast<uint8_t>(value >> 48);
        buf_[pos_++] = static_cast<uint8_t>(value >> 40);
        buf_[pos_++] = static_cast<uint8_t>(value >> 32);
        buf_[pos_++] = static_cast<uint8_t>(value >> 24);
        buf_[pos_++] = static_cast<uint8_t>(value >> 16);
        buf_[pos_++] = static_cast<uint8_t>(value >> 8);
        buf_[pos_++] = static_cast<uint8_t>(value);
    }
    return Error::Success;
}

Error TlvEncoder::writeType(uint32_t type) {
    return writeVarNumber(type);
}

Error TlvEncoder::writeLength(size_t length) {
    return writeVarNumber(length);
}

Error TlvEncoder::writeBytes(const uint8_t* data, size_t len) {
    if (remaining() < len) {
        return Error::BufferTooSmall;
    }
    std::memcpy(buf_ + pos_, data, len);
    pos_ += len;
    return Error::Success;
}

Error TlvEncoder::writeTlv(uint32_t type, const uint8_t* value, size_t valueLen) {
    Error err = writeType(type);
    if (err != Error::Success) {
        return err;
    }

    err = writeLength(valueLen);
    if (err != Error::Success) {
        return err;
    }

    if (valueLen > 0) {
        err = writeBytes(value, valueLen);
        if (err != Error::Success) {
            return err;
        }
    }

    return Error::Success;
}

Error TlvEncoder::writeTlvNonNegativeInteger(uint32_t type, uint64_t value) {
    const size_t intSize = nonNegativeIntegerSize(value);

    Error err = writeType(type);
    if (err != Error::Success) {
        return err;
    }

    err = writeLength(intSize);
    if (err != Error::Success) {
        return err;
    }

    return writeNonNegativeInteger(value);
}

// =============================================================================
// TlvDecoder
// =============================================================================

TlvDecoder::TlvDecoder(const uint8_t* buf, size_t len) : buf_(buf), len_(len) {}

Result<uint64_t> TlvDecoder::readVarNumber() {
    if (remaining() < 1) {
        return {.value = 0, .error = Error::DecodeFailed};
    }

    const uint8_t firstByte = buf_[pos_++];

    if (firstByte <= 252) {
        return {.value = firstByte, .error = Error::Success};
    } else if (firstByte == 253) {
        if (remaining() < 2) {
            return {.value = 0, .error = Error::DecodeFailed};
        }
        const uint64_t val =
            (static_cast<uint64_t>(buf_[pos_]) << 8) | static_cast<uint64_t>(buf_[pos_ + 1]);
        pos_ += 2;
        return {.value = val, .error = Error::Success};
    } else if (firstByte == 254) {
        if (remaining() < 4) {
            return {.value = 0, .error = Error::DecodeFailed};
        }
        const uint64_t val = (static_cast<uint64_t>(buf_[pos_]) << 24) |
                             (static_cast<uint64_t>(buf_[pos_ + 1]) << 16) |
                             (static_cast<uint64_t>(buf_[pos_ + 2]) << 8) |
                             static_cast<uint64_t>(buf_[pos_ + 3]);
        pos_ += 4;
        return {.value = val, .error = Error::Success};
    } else {  // firstByte == 255
        if (remaining() < 8) {
            return {.value = 0, .error = Error::DecodeFailed};
        }
        const uint64_t val = (static_cast<uint64_t>(buf_[pos_]) << 56) |
                             (static_cast<uint64_t>(buf_[pos_ + 1]) << 48) |
                             (static_cast<uint64_t>(buf_[pos_ + 2]) << 40) |
                             (static_cast<uint64_t>(buf_[pos_ + 3]) << 32) |
                             (static_cast<uint64_t>(buf_[pos_ + 4]) << 24) |
                             (static_cast<uint64_t>(buf_[pos_ + 5]) << 16) |
                             (static_cast<uint64_t>(buf_[pos_ + 6]) << 8) |
                             static_cast<uint64_t>(buf_[pos_ + 7]);
        pos_ += 8;
        return {.value = val, .error = Error::Success};
    }
}

Result<uint64_t> TlvDecoder::readNonNegativeInteger(size_t numBytes) {
    if (remaining() < numBytes) {
        return {.value = 0, .error = Error::DecodeFailed};
    }

    uint64_t val = 0;
    for (size_t idx = 0; idx < numBytes; ++idx) {
        val = (val << 8) | buf_[pos_++];
    }

    return {.value = val, .error = Error::Success};
}

Result<uint32_t> TlvDecoder::readType() {
    auto result = readVarNumber();
    if (!result.ok()) {
        return {.value = 0, .error = result.error};
    }
    // NDN TLV type must fit in 32 bits
    if (result.value > 0xFFFFFFFF) {
        return {.value = 0, .error = Error::DecodeFailed};
    }
    return {.value = static_cast<uint32_t>(result.value), .error = Error::Success};
}

Result<size_t> TlvDecoder::readLength() {
    auto result = readVarNumber();
    if (!result.ok()) {
        return {.value = 0, .error = result.error};
    }
    return {.value = static_cast<size_t>(result.value), .error = Error::Success};
}

Result<TlvDecoder::TlvHeader> TlvDecoder::readTlvHeader() {
    auto typeResult = readType();
    if (!typeResult.ok()) {
        return {.value = {.type = 0, .length = 0}, .error = typeResult.error};
    }

    auto lengthResult = readLength();
    if (!lengthResult.ok()) {
        return {.value = {.type = 0, .length = 0}, .error = lengthResult.error};
    }

    return {.value = {.type = typeResult.value, .length = lengthResult.value},
            .error = Error::Success};
}

Error TlvDecoder::readBytes(uint8_t* out, size_t len) {
    if (remaining() < len) {
        return Error::DecodeFailed;
    }
    std::memcpy(out, buf_ + pos_, len);
    pos_ += len;
    return Error::Success;
}

Error TlvDecoder::skip(size_t len) {
    if (remaining() < len) {
        return Error::DecodeFailed;
    }
    pos_ += len;
    return Error::Success;
}

}  // namespace ndn
