#include "ndn/name.hpp"
#include "ndn/tlv.hpp"
#include <cstring>

namespace ndn {

namespace {

// Hex decode from URI
int hexValue(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

}  // namespace

Result<Name> Name::fromUri(std::string_view uri) {
    Name name;

    // Skip leading "ndn:" prefix (optional)
    if (uri.starts_with("ndn:")) {
        uri = uri.substr(4);
    }

    // Empty name
    if (uri.empty() || uri == "/") {
        return {.value = name, .error = Error::Success};
    }

    // Skip leading "/"
    if (uri[0] == '/') {
        uri = uri.substr(1);
    }

    // Parse components
    size_t start = 0;
    while (start < uri.size()) {
        // Find the next "/"
        size_t end = uri.find('/', start);
        if (end == std::string_view::npos) {
            end = uri.size();
        }

        const std::string_view compStr = uri.substr(start, end - start);

        if (!compStr.empty()) {
            // URL decode processing
            uint8_t compBuf[NAME_MAX_LENGTH];
            size_t compLen = 0;

            for (size_t i = 0; i < compStr.size() && compLen < NAME_MAX_LENGTH; ++i) {
                if (compStr[i] == '%' && i + 2 < compStr.size()) {
                    const int hi = hexValue(compStr[i + 1]);
                    const int lo = hexValue(compStr[i + 2]);
                    if (hi >= 0 && lo >= 0) {
                        compBuf[compLen++] = static_cast<uint8_t>((hi << 4) | lo);
                        i += 2;
                        continue;
                    }
                }
                compBuf[compLen++] = static_cast<uint8_t>(compStr[i]);
            }

            const Error err = name.appendComponentInternal(compBuf, compLen);
            if (err != Error::Success) {
                return {.value = Name{}, .error = err};
            }
        }

        start = end + 1;
    }

    return {.value = name, .error = Error::Success};
}

Result<Name> Name::fromWire(const uint8_t* buf, size_t len, size_t* bytesRead) {
    Name name;
    TlvDecoder decoder(buf, len);

    // Read Name TLV header
    auto headerResult = decoder.readTlvHeader();
    if (!headerResult.ok()) {
        return {.value = Name{}, .error = headerResult.error};
    }

    if (headerResult.value.type != tlv::Name) {
        return {.value = Name{}, .error = Error::DecodeFailed};
    }

    const size_t nameValueLen = headerResult.value.length;
    if (decoder.remaining() < nameValueLen) {
        return {.value = Name{}, .error = Error::DecodeFailed};
    }

    // Start position of Name value
    const size_t nameValueStart = decoder.position();

    // Parse components
    while (decoder.position() < nameValueStart + nameValueLen) {
        auto compHeader = decoder.readTlvHeader();
        if (!compHeader.ok()) {
            return {.value = Name{}, .error = compHeader.error};
        }

        // Only GenericNameComponent (0x08) is supported
        if (compHeader.value.type != tlv::GenericNameComponent) {
            // Skip other types
            if (decoder.skip(compHeader.value.length) != Error::Success) {
                return {.value = Name{}, .error = Error::DecodeFailed};
            }
            continue;
        }

        if (decoder.remaining() < compHeader.value.length) {
            return {.value = Name{}, .error = Error::DecodeFailed};
        }

        const Error err = name.appendComponentInternal(decoder.current(), compHeader.value.length);
        if (err != Error::Success) {
            return {.value = Name{}, .error = err};
        }

        decoder.skip(compHeader.value.length);
    }

    if (bytesRead != nullptr) {
        *bytesRead = decoder.position();
    }

    return {.value = name, .error = Error::Success};
}

size_t Name::toUri(char* buf, size_t bufSize) const {
    if (bufSize == 0) {
        return 0;
    }

    size_t written = 0;

    if (numComponents_ == 0) {
        if (bufSize >= 2) {
            buf[0] = '/';
            buf[1] = '\0';
            return 1;
        }
        buf[0] = '\0';
        return 0;
    }

    for (size_t i = 0; i < numComponents_; ++i) {
        // Write "/"
        if (written < bufSize - 1) {
            buf[written++] = '/';
        }

        const NameComponent comp = component(i);

        // Write component value
        for (size_t j = 0; j < comp.size && written < bufSize - 1; ++j) {
            const uint8_t c = comp.value[j];
            // Printable characters as-is, others are percent-encoded
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                c == '-' || c == '.' || c == '_' || c == '~') {
                buf[written++] = static_cast<char>(c);
            } else if (written + 3 < bufSize) {
                static const char hex[] = "0123456789ABCDEF";
                buf[written++] = '%';
                buf[written++] = hex[c >> 4];
                buf[written++] = hex[c & 0x0F];
            }
        }
    }

    buf[written] = '\0';
    return written;
}

Error Name::encode(uint8_t* buf, size_t bufSize, size_t& encodedLen) const {
    // Internal buffer stores only component TLVs
    // Build the entire Name TLV

    const size_t nameValueLen = length_;  // Total length of component TLVs
    const size_t headerSize = varNumberSize(tlv::Name) + varNumberSize(nameValueLen);
    const size_t totalSize = headerSize + nameValueLen;

    if (bufSize < totalSize) {
        return Error::BufferTooSmall;
    }

    TlvEncoder encoder(buf, bufSize);

    Error err = encoder.writeType(tlv::Name);
    if (err != Error::Success) {
        return err;
    }

    err = encoder.writeLength(nameValueLen);
    if (err != Error::Success) {
        return err;
    }

    err = encoder.writeBytes(buffer_.data(), length_);
    if (err != Error::Success) {
        return err;
    }

    encodedLen = encoder.size();
    return Error::Success;
}

NameComponent Name::component(size_t index) const {
    if (index >= numComponents_) {
        return {.value = nullptr, .size = 0};
    }

    const auto& comp = components_[index];
    return {.value = buffer_.data() + comp.offset, .size = comp.length};
}

Error Name::appendComponent(std::string_view comp) {
    return appendComponentInternal(reinterpret_cast<const uint8_t*>(comp.data()), comp.size());
}

Error Name::appendComponent(const uint8_t* value, size_t len) {
    return appendComponentInternal(value, len);
}

Error Name::appendComponentInternal(const uint8_t* value, size_t len) {
    if (numComponents_ >= NAME_MAX_COMPONENTS) {
        return Error::TooManyComponents;
    }

    // Calculate component TLV size
    const size_t tlvSize = varNumberSize(tlv::GenericNameComponent) + varNumberSize(len) + len;

    if (length_ + tlvSize > NAME_MAX_LENGTH) {
        return Error::NameTooLong;
    }

    // Store as TLV in the buffer
    TlvEncoder encoder(buffer_.data() + length_, buffer_.size() - length_);

    Error err = encoder.writeType(tlv::GenericNameComponent);
    if (err != Error::Success) {
        return err;
    }

    err = encoder.writeLength(len);
    if (err != Error::Success) {
        return err;
    }

    // Record the offset of the component value
    const size_t valueOffset = length_ + encoder.size();

    err = encoder.writeBytes(value, len);
    if (err != Error::Success) {
        return err;
    }

    // Record component information
    components_[numComponents_].offset = static_cast<uint16_t>(valueOffset);
    components_[numComponents_].length = static_cast<uint16_t>(len);
    numComponents_++;

    length_ += encoder.size();

    return Error::Success;
}

int Name::compare(const Name& other) const {
    const size_t minComponents =
        (numComponents_ < other.numComponents_) ? numComponents_ : other.numComponents_;

    for (size_t i = 0; i < minComponents; ++i) {
        const NameComponent a = component(i);
        const NameComponent b = other.component(i);

        // Compare by length
        if (a.size != b.size) {
            return (a.size < b.size) ? -1 : 1;
        }

        // Compare by byte sequence
        const int cmp = std::memcmp(a.value, b.value, a.size);
        if (cmp != 0) {
            return cmp;
        }
    }

    // Compare by number of components
    if (numComponents_ < other.numComponents_) {
        return -1;
    }
    if (numComponents_ > other.numComponents_) {
        return 1;
    }
    return 0;
}

bool Name::equals(const Name& other) const {
    return compare(other) == 0;
}

bool Name::isPrefixOf(const Name& other) const {
    if (numComponents_ > other.numComponents_) {
        return false;
    }

    for (size_t i = 0; i < numComponents_; ++i) {
        const NameComponent a = component(i);
        const NameComponent b = other.component(i);

        if (a.size != b.size) {
            return false;
        }

        if (std::memcmp(a.value, b.value, a.size) != 0) {
            return false;
        }
    }

    return true;
}

uint32_t Name::hash() const {
    // Simple DJB2 hash
    uint32_t h = 5381;
    for (size_t i = 0; i < length_; ++i) {
        h = ((h << 5) + h) + buffer_[i];
    }
    return h;
}

}  // namespace ndn
