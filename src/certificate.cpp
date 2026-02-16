/**
 * @file certificate.cpp
 * @brief NDN Certificate implementation
 */

#include "ndn/certificate.hpp"

#include "ndn/crypto.hpp"
#include "ndn/tlv.hpp"

#include <cstring>

namespace ndn {

// =============================================================================
// ValidityPeriod implementation
// =============================================================================

namespace {

/**
 * @brief Convert date/time to ISO 8601 format string
 */
void formatTimestamp(char* out, uint16_t year, uint8_t month, uint8_t day, uint8_t hour,
                     uint8_t minute, uint8_t second) {
    // YYYYMMDDThhmmss
    out[0] = '0' + (year / 1000) % 10;
    out[1] = '0' + (year / 100) % 10;
    out[2] = '0' + (year / 10) % 10;
    out[3] = '0' + year % 10;
    out[4] = '0' + month / 10;
    out[5] = '0' + month % 10;
    out[6] = '0' + day / 10;
    out[7] = '0' + day % 10;
    out[8] = 'T';
    out[9] = '0' + hour / 10;
    out[10] = '0' + hour % 10;
    out[11] = '0' + minute / 10;
    out[12] = '0' + minute % 10;
    out[13] = '0' + second / 10;
    out[14] = '0' + second % 10;
}

/**
 * @brief Validate timestamp string format
 */
bool isValidTimestamp(std::string_view ts) {
    if (ts.size() != VALIDITY_TIMESTAMP_SIZE) {
        return false;
    }
    // Simple check: position of 'T' and digits
    if (ts[8] != 'T') {
        return false;
    }
    for (size_t i = 0; i < VALIDITY_TIMESTAMP_SIZE; ++i) {
        if (i == 8) {
            continue;  // 'T'
        }
        if (ts[i] < '0' || ts[i] > '9') {
            return false;
        }
    }
    return true;
}

/**
 * @brief Compare two timestamp strings
 * @return negative if a < b, 0 if a == b, positive if a > b
 */
int compareTimestamp(const char* a, const char* b) {
    return std::memcmp(a, b, VALIDITY_TIMESTAMP_SIZE);
}

}  // namespace

Result<ValidityPeriod> ValidityPeriod::fromStrings(std::string_view notBefore,
                                                   std::string_view notAfter) {
    ValidityPeriod vp;

    if (!isValidTimestamp(notBefore) || !isValidTimestamp(notAfter)) {
        return {.value = ValidityPeriod{}, .error = Error::InvalidParam};
    }

    std::memcpy(vp.notBefore_.data(), notBefore.data(), VALIDITY_TIMESTAMP_SIZE);
    std::memcpy(vp.notAfter_.data(), notAfter.data(), VALIDITY_TIMESTAMP_SIZE);

    return {.value = vp, .error = Error::Success};
}

Result<ValidityPeriod> ValidityPeriod::fromWire(const uint8_t* buf, size_t len, size_t* bytesRead) {
    ValidityPeriod vp;
    TlvDecoder decoder(buf, len);

    // ValidityPeriod TLV header
    auto header = decoder.readTlvHeader();
    if (!header.ok()) {
        return {.value = ValidityPeriod{}, .error = header.error};
    }

    if (header.value.type != tlv::ValidityPeriod) {
        return {.value = ValidityPeriod{}, .error = Error::InvalidPacket};
    }

    const size_t vpEnd = decoder.position() + header.value.length;

    // NotBefore
    auto nbHeader = decoder.readTlvHeader();
    if (!nbHeader.ok() || nbHeader.value.type != tlv::NotBefore) {
        return {.value = ValidityPeriod{}, .error = Error::InvalidPacket};
    }
    if (nbHeader.value.length != VALIDITY_TIMESTAMP_SIZE) {
        return {.value = ValidityPeriod{}, .error = Error::InvalidPacket};
    }
    Error err = decoder.readBytes(reinterpret_cast<uint8_t*>(vp.notBefore_.data()),
                                  VALIDITY_TIMESTAMP_SIZE);
    if (err != Error::Success) {
        return {.value = ValidityPeriod{}, .error = err};
    }

    // NotAfter
    auto naHeader = decoder.readTlvHeader();
    if (!naHeader.ok() || naHeader.value.type != tlv::NotAfter) {
        return {.value = ValidityPeriod{}, .error = Error::InvalidPacket};
    }
    if (naHeader.value.length != VALIDITY_TIMESTAMP_SIZE) {
        return {.value = ValidityPeriod{}, .error = Error::InvalidPacket};
    }
    err =
        decoder.readBytes(reinterpret_cast<uint8_t*>(vp.notAfter_.data()), VALIDITY_TIMESTAMP_SIZE);
    if (err != Error::Success) {
        return {.value = ValidityPeriod{}, .error = err};
    }

    if (decoder.position() != vpEnd) {
        return {.value = ValidityPeriod{}, .error = Error::DecodeFailed};
    }

    if (bytesRead != nullptr) {
        *bytesRead = decoder.position();
    }

    return {.value = vp, .error = Error::Success};
}

Error ValidityPeriod::encode(uint8_t* buf, size_t bufSize, size_t& encodedLen) const {
    // Encode ValidityPeriod contents
    uint8_t valueBuf[64];
    TlvEncoder valueEncoder(valueBuf, sizeof(valueBuf));

    // NotBefore
    Error err =
        valueEncoder.writeTlv(tlv::NotBefore, reinterpret_cast<const uint8_t*>(notBefore_.data()),
                              VALIDITY_TIMESTAMP_SIZE);
    if (err != Error::Success) {
        return err;
    }

    // NotAfter
    err = valueEncoder.writeTlv(tlv::NotAfter, reinterpret_cast<const uint8_t*>(notAfter_.data()),
                                VALIDITY_TIMESTAMP_SIZE);
    if (err != Error::Success) {
        return err;
    }

    // ValidityPeriod TLV
    TlvEncoder encoder(buf, bufSize);
    err = encoder.writeTlv(tlv::ValidityPeriod, valueBuf, valueEncoder.size());
    if (err != Error::Success) {
        return err;
    }

    encodedLen = encoder.size();
    return Error::Success;
}

Error ValidityPeriod::setNotBefore(uint16_t year, uint8_t month, uint8_t day, uint8_t hour,
                                   uint8_t minute, uint8_t second) {
    formatTimestamp(notBefore_.data(), year, month, day, hour, minute, second);
    return Error::Success;
}

Error ValidityPeriod::setNotBefore(std::string_view timestamp) {
    if (!isValidTimestamp(timestamp)) {
        return Error::InvalidParam;
    }
    std::memcpy(notBefore_.data(), timestamp.data(), VALIDITY_TIMESTAMP_SIZE);
    return Error::Success;
}

Error ValidityPeriod::setNotAfter(uint16_t year, uint8_t month, uint8_t day, uint8_t hour,
                                  uint8_t minute, uint8_t second) {
    formatTimestamp(notAfter_.data(), year, month, day, hour, minute, second);
    return Error::Success;
}

Error ValidityPeriod::setNotAfter(std::string_view timestamp) {
    if (!isValidTimestamp(timestamp)) {
        return Error::InvalidParam;
    }
    std::memcpy(notAfter_.data(), timestamp.data(), VALIDITY_TIMESTAMP_SIZE);
    return Error::Success;
}

bool ValidityPeriod::isValidAt(std::string_view currentTimestamp) const {
    if (currentTimestamp.size() != VALIDITY_TIMESTAMP_SIZE) {
        return false;
    }
    // notBefore <= current <= notAfter
    return compareTimestamp(notBefore_.data(), currentTimestamp.data()) <= 0 &&
           compareTimestamp(currentTimestamp.data(), notAfter_.data()) <= 0;
}

bool ValidityPeriod::equals(const ValidityPeriod& other) const {
    return std::memcmp(notBefore_.data(), other.notBefore_.data(), VALIDITY_TIMESTAMP_SIZE) == 0 &&
           std::memcmp(notAfter_.data(), other.notAfter_.data(), VALIDITY_TIMESTAMP_SIZE) == 0;
}

// =============================================================================
// Certificate implementation
// =============================================================================

Result<Certificate> Certificate::fromData(const Data& data) {
    Certificate cert;

    // ContentType must be Key
    if (data.contentType() != ContentType::Key) {
        return {.value = Certificate{}, .error = Error::InvalidPacket};
    }

    // Parse name: /<IdentityName>/KEY/<KeyId>/<IssuerId>/<Version>
    const Name& name = data.name();
    if (name.componentCount() < 4) {
        return {.value = Certificate{}, .error = Error::InvalidPacket};
    }

    // Find "KEY" component
    size_t keyIndex = 0;
    bool foundKey = false;
    for (size_t i = 0; i < name.componentCount(); ++i) {
        auto comp = name.component(i);
        if (comp.size == 3 && std::memcmp(comp.value, "KEY", 3) == 0) {
            keyIndex = i;
            foundKey = true;
            break;
        }
    }

    if (!foundKey || keyIndex == 0 || name.componentCount() < keyIndex + 3) {
        return {.value = Certificate{}, .error = Error::InvalidPacket};
    }

    // Identity name = components before "KEY"
    // Build identity name
    Name identityName;
    for (size_t i = 0; i < keyIndex; ++i) {
        auto comp = name.component(i);
        identityName.appendComponent(comp.value, comp.size);
    }
    cert.identityName_ = identityName;

    // Key ID = component after "KEY"
    auto keyIdComp = name.component(keyIndex + 1);
    if (keyIdComp.size <= cert.keyId_.size()) {
        std::memcpy(cert.keyId_.data(), keyIdComp.value, keyIdComp.size);
        cert.keyIdSize_ = keyIdComp.size;
    }

    // Issuer ID = component after Key ID
    auto issuerIdComp = name.component(keyIndex + 2);
    if (issuerIdComp.size <= cert.issuerId_.size()) {
        std::memcpy(cert.issuerId_.data(), issuerIdComp.value, issuerIdComp.size);
        cert.issuerIdSize_ = issuerIdComp.size;
    }

    // Version = last component (if it's a version component, decode it)
    if (name.componentCount() > keyIndex + 3) {
        auto versionComp = name.component(keyIndex + 3);
        // Simple version: just use the bytes as version number
        uint64_t version = 0;
        for (size_t i = 0; i < versionComp.size && i < 8; ++i) {
            version = (version << 8) | versionComp.value[i];
        }
        cert.version_ = version;
    }

    // Public key = content
    if (data.hasContent()) {
        const size_t keySize = data.contentSize();
        if (keySize > CERTIFICATE_MAX_KEY_SIZE) {
            return {.value = Certificate{}, .error = Error::BufferTooSmall};
        }
        std::memcpy(cert.publicKey_.data(), data.content(), keySize);
        cert.publicKeySize_ = keySize;
    }

    // Signature info
    cert.signatureType_ = data.signatureType();
    if (data.hasSignature()) {
        const size_t sigSize = data.signatureValueSize();
        if (sigSize <= SIGNATURE_MAX_SIZE) {
            std::memcpy(cert.signatureValue_.data(), data.signatureValue(), sigSize);
            cert.signatureSize_ = sigSize;
        }
    }

    return {.value = cert, .error = Error::Success};
}

Result<Certificate> Certificate::fromWire(const uint8_t* buf, size_t len) {
    // First decode as Data
    auto dataResult = Data::fromWire(buf, len);
    if (!dataResult.ok()) {
        return {.value = Certificate{}, .error = dataResult.error};
    }

    return fromData(dataResult.value);
}

Error Certificate::toData(Data& data) const {
    // Build certificate name
    Name certName;
    Error err = buildName(certName);
    if (err != Error::Success) {
        return err;
    }

    data.setName(certName);
    data.setContentType(ContentType::Key);

    // Set public key as content
    if (publicKeySize_ > 0) {
        err = data.setContent(publicKey_.data(), publicKeySize_);
        if (err != Error::Success) {
            return err;
        }
    }

    // Set freshness period (recommended ~1 hour)
    data.setFreshnessPeriod(3600000);

    // Copy signature info
    data.setSignatureType(signatureType_);

    return Error::Success;
}

Error Certificate::encode(uint8_t* buf, size_t bufSize, size_t& encodedLen) const {
    uint8_t valueBuf[PACKET_MAX_SIZE];

    // Encode signed portion (Name + MetaInfo + Content + SignatureInfo)
    size_t signedLen = 0;
    Error err = encodeSignedPortion(valueBuf, sizeof(valueBuf), signedLen);
    if (err != Error::Success) {
        return err;
    }

    TlvEncoder valueEncoder(valueBuf + signedLen, sizeof(valueBuf) - signedLen);

    // SignatureValue
    err = valueEncoder.writeTlv(tlv::SignatureValue, signatureValue_.data(), signatureSize_);
    if (err != Error::Success) {
        return err;
    }

    // Data TLV header
    const size_t valueLen = signedLen + valueEncoder.size();
    const size_t headerSize = varNumberSize(tlv::Data) + varNumberSize(valueLen);
    const size_t totalSize = headerSize + valueLen;

    if (bufSize < totalSize) {
        return Error::BufferTooSmall;
    }

    TlvEncoder encoder(buf, bufSize);
    err = encoder.writeType(tlv::Data);
    if (err != Error::Success) {
        return err;
    }

    err = encoder.writeLength(valueLen);
    if (err != Error::Success) {
        return err;
    }

    err = encoder.writeBytes(valueBuf, valueLen);
    if (err != Error::Success) {
        return err;
    }

    encodedLen = encoder.size();
    return Error::Success;
}

Certificate& Certificate::setIdentityName(const Name& name) {
    identityName_ = name;
    return *this;
}

Error Certificate::setIdentityName(std::string_view uri) {
    auto result = Name::fromUri(uri);
    if (!result.ok()) {
        return result.error;
    }
    identityName_ = result.value;
    return Error::Success;
}

Error Certificate::setKeyId(const uint8_t* id, size_t len) {
    if (len > keyId_.size()) {
        return Error::BufferTooSmall;
    }
    std::memcpy(keyId_.data(), id, len);
    keyIdSize_ = len;
    return Error::Success;
}

Error Certificate::setIssuerId(const uint8_t* id, size_t len) {
    if (len > issuerId_.size()) {
        return Error::BufferTooSmall;
    }
    std::memcpy(issuerId_.data(), id, len);
    issuerIdSize_ = len;
    return Error::Success;
}

Error Certificate::setIssuerId(std::string_view id) {
    return setIssuerId(reinterpret_cast<const uint8_t*>(id.data()), id.size());
}

Certificate& Certificate::setVersion(uint64_t version) {
    version_ = version;
    return *this;
}

Error Certificate::setPublicKey(const uint8_t* key, size_t len) {
    if (len > CERTIFICATE_MAX_KEY_SIZE) {
        return Error::BufferTooSmall;
    }
    std::memcpy(publicKey_.data(), key, len);
    publicKeySize_ = len;
    return Error::Success;
}

Certificate& Certificate::setValidity(const ValidityPeriod& validity) {
    validity_ = validity;
    return *this;
}

Certificate& Certificate::setSignatureType(SignatureType type) {
    signatureType_ = type;
    return *this;
}

Error Certificate::buildName(Name& name) const {
    name = Name();

    // Copy identity name components
    for (size_t i = 0; i < identityName_.componentCount(); ++i) {
        auto comp = identityName_.component(i);
        const Error err = name.appendComponent(comp.value, comp.size);
        if (err != Error::Success) {
            return err;
        }
    }

    // "KEY" component
    Error err = name.appendComponent(reinterpret_cast<const uint8_t*>("KEY"), 3);
    if (err != Error::Success) {
        return err;
    }

    // Key ID component
    if (keyIdSize_ > 0) {
        err = name.appendComponent(keyId_.data(), keyIdSize_);
        if (err != Error::Success) {
            return err;
        }
    }

    // Issuer ID component
    if (issuerIdSize_ > 0) {
        err = name.appendComponent(issuerId_.data(), issuerIdSize_);
        if (err != Error::Success) {
            return err;
        }
    }

    // Version component (encode as big-endian bytes)
    if (version_ > 0) {
        uint8_t versionBytes[8];
        size_t versionLen = 0;
        uint64_t v = version_;

        // Calculate number of bytes needed
        if (v <= 0xFF) {
            versionLen = 1;
        } else if (v <= 0xFFFF) {
            versionLen = 2;
        } else if (v <= 0xFFFFFF) {
            versionLen = 3;
        } else if (v <= 0xFFFFFFFF) {
            versionLen = 4;
        } else {
            versionLen = 8;
        }

        // Encode big-endian
        for (size_t i = 0; i < versionLen; ++i) {
            versionBytes[versionLen - 1 - i] = static_cast<uint8_t>(v & 0xFF);
            v >>= 8;
        }

        err = name.appendComponent(versionBytes, versionLen);
        if (err != Error::Success) {
            return err;
        }
    }

    return Error::Success;
}

Error Certificate::encodeSignedPortion(uint8_t* buf, size_t bufSize, size_t& encodedLen) const {
    // Build certificate name
    Name certName;
    Error err = buildName(certName);
    if (err != Error::Success) {
        return err;
    }

    TlvEncoder encoder(buf, bufSize);

    // Name
    size_t nameLen = 0;
    err = certName.encode(encoder.current(), encoder.remaining(), nameLen);
    if (err != Error::Success) {
        return err;
    }
    encoder.setPosition(encoder.position() + nameLen);

    // MetaInfo (ContentType=Key, FreshnessPeriod=1 hour)
    {
        uint8_t metaBuf[24];
        TlvEncoder metaEncoder(metaBuf, sizeof(metaBuf));
        metaEncoder.writeTlvNonNegativeInteger(tlv::ContentType,
                                               static_cast<uint8_t>(ContentType::Key));
        metaEncoder.writeTlvNonNegativeInteger(tlv::FreshnessPeriod, 3600000);
        encoder.writeTlv(tlv::MetaInfo, metaBuf, metaEncoder.size());
    }

    // Content (public key)
    if (publicKeySize_ > 0) {
        encoder.writeTlv(tlv::Content, publicKey_.data(), publicKeySize_);
    }

    // SignatureInfo (SignatureType + ValidityPeriod)
    {
        uint8_t sigInfoBuf[96];
        TlvEncoder sigInfoEncoder(sigInfoBuf, sizeof(sigInfoBuf));
        sigInfoEncoder.writeTlvNonNegativeInteger(tlv::SignatureType,
                                                  static_cast<uint8_t>(signatureType_));

        size_t vpLen = 0;
        uint8_t vpBuf[64];
        validity_.encode(vpBuf, sizeof(vpBuf), vpLen);
        sigInfoEncoder.writeBytes(vpBuf, vpLen);

        encoder.writeTlv(tlv::SignatureInfo, sigInfoBuf, sigInfoEncoder.size());
    }

    encodedLen = encoder.size();
    return Error::Success;
}

Error Certificate::signWithDigestSha256() {
    signatureType_ = SignatureType::DigestSha256;

    uint8_t signedBuf[PACKET_MAX_SIZE];
    size_t signedLen = 0;
    Error err = encodeSignedPortion(signedBuf, sizeof(signedBuf), signedLen);
    if (err != Error::Success) {
        return err;
    }

    err = crypto::sha256(signedBuf, signedLen, signatureValue_.data());
    if (err != Error::Success) {
        return err;
    }

    signatureSize_ = SHA256_DIGEST_SIZE;
    return Error::Success;
}

Error Certificate::signWithHmac(const uint8_t* key, size_t keyLen) {
    if (key == nullptr || keyLen == 0) {
        return Error::InvalidParam;
    }

    signatureType_ = SignatureType::SignatureHmacWithSha256;

    uint8_t signedBuf[PACKET_MAX_SIZE];
    size_t signedLen = 0;
    Error err = encodeSignedPortion(signedBuf, sizeof(signedBuf), signedLen);
    if (err != Error::Success) {
        return err;
    }

    err = crypto::hmacSha256(key, keyLen, signedBuf, signedLen, signatureValue_.data());
    if (err != Error::Success) {
        return err;
    }

    signatureSize_ = HMAC_SHA256_SIZE;
    return Error::Success;
}

bool Certificate::verifyDigestSha256() const {
    if (signatureType_ != SignatureType::DigestSha256) {
        return false;
    }
    if (signatureSize_ != SHA256_DIGEST_SIZE) {
        return false;
    }

    uint8_t signedBuf[PACKET_MAX_SIZE];
    size_t signedLen = 0;
    if (encodeSignedPortion(signedBuf, sizeof(signedBuf), signedLen) != Error::Success) {
        return false;
    }

    uint8_t computed[SHA256_DIGEST_SIZE];
    if (crypto::sha256(signedBuf, signedLen, computed) != Error::Success) {
        return false;
    }

    return crypto::constantTimeCompare(computed, signatureValue_.data(), SHA256_DIGEST_SIZE);
}

bool Certificate::verifyHmac(const uint8_t* key, size_t keyLen) const {
    if (key == nullptr || keyLen == 0) {
        return false;
    }
    if (signatureType_ != SignatureType::SignatureHmacWithSha256) {
        return false;
    }
    if (signatureSize_ != HMAC_SHA256_SIZE) {
        return false;
    }

    uint8_t signedBuf[PACKET_MAX_SIZE];
    size_t signedLen = 0;
    if (encodeSignedPortion(signedBuf, sizeof(signedBuf), signedLen) != Error::Success) {
        return false;
    }

    uint8_t computed[HMAC_SHA256_SIZE];
    if (crypto::hmacSha256(key, keyLen, signedBuf, signedLen, computed) != Error::Success) {
        return false;
    }

    return crypto::constantTimeCompare(computed, signatureValue_.data(), HMAC_SHA256_SIZE);
}

bool Certificate::isValidAt(std::string_view timestamp) const {
    return validity_.isValidAt(timestamp);
}

}  // namespace ndn
