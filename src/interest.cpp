#include "ndn/interest.hpp"

#include "ndn/crypto.hpp"
#include "ndn/tlv.hpp"

#include <algorithm>
#include <cstring>

namespace ndn {

Interest::Interest(const Name& name) : name_(name) {}

Interest& Interest::setName(const Name& name) {
    name_ = name;
    return *this;
}

Error Interest::setName(std::string_view uri) {
    auto result = Name::fromUri(uri);
    if (!result.ok()) {
        return result.error;
    }
    name_ = result.value;
    return Error::Success;
}

Interest& Interest::setNonce(uint32_t nonce) {
    nonce_ = nonce;
    return *this;
}

Interest& Interest::generateNonce() {
    nonce_ = generateRandomNonce();
    return *this;
}

Interest& Interest::setLifetime(uint32_t lifetimeMs) {
    lifetime_ = lifetimeMs;
    return *this;
}

Interest& Interest::setHopLimit(uint8_t limit) {
    hopLimit_ = limit;
    return *this;
}

Interest& Interest::decrementHopLimit() {
    if (hopLimit_ && *hopLimit_ > 0) {
        hopLimit_ = *hopLimit_ - 1;
    }
    return *this;
}

Interest& Interest::setCanBePrefix(bool canBePrefix) {
    canBePrefix_ = canBePrefix;
    return *this;
}

Interest& Interest::setMustBeFresh(bool mustBeFresh) {
    mustBeFresh_ = mustBeFresh;
    return *this;
}

Error Interest::addForwardingHint(const Name& name) {
    if (fwHintCount_ >= FW_HINT_MAX_COUNT) {
        return Error::Full;
    }
    fwHints_[fwHintCount_++] = name;
    return Error::Success;
}

Error Interest::addForwardingHint(std::string_view uri) {
    auto result = Name::fromUri(uri);
    if (!result.ok()) {
        return result.error;
    }
    return addForwardingHint(result.value);
}

const Name* Interest::forwardingHint(size_t index) const {
    if (index >= fwHintCount_) {
        return nullptr;
    }
    return &fwHints_[index];
}

void Interest::clearForwardingHints() {
    fwHintCount_ = 0;
}

Interest& Interest::setApplicationParameters(const uint8_t* params, size_t len) {
    len = std::min(len, static_cast<size_t>(APP_PARAMS_MAX_SIZE));
    std::memcpy(appParams_, params, len);
    appParamsLen_ = len;
    return *this;
}

Interest& Interest::setSignatureSeqNum(uint64_t seqNum) {
    signatureSeqNum_ = seqNum;
    return *this;
}

Interest& Interest::setKeyLocator(const Name& name) {
    keyLocator_ = name;
    hasKeyLocator_ = true;
    return *this;
}

Interest& Interest::clearKeyLocator() {
    keyLocator_ = Name{};
    hasKeyLocator_ = false;
    return *this;
}

void Interest::generateSignatureNonce() {
    // Generate 8-byte random nonce
    const uint32_t rand1 = generateRandomNonce();
    const uint32_t rand2 = generateRandomNonce();
    signatureNonce_[0] = static_cast<uint8_t>(rand1 >> 24);
    signatureNonce_[1] = static_cast<uint8_t>(rand1 >> 16);
    signatureNonce_[2] = static_cast<uint8_t>(rand1 >> 8);
    signatureNonce_[3] = static_cast<uint8_t>(rand1);
    signatureNonce_[4] = static_cast<uint8_t>(rand2 >> 24);
    signatureNonce_[5] = static_cast<uint8_t>(rand2 >> 16);
    signatureNonce_[6] = static_cast<uint8_t>(rand2 >> 8);
    signatureNonce_[7] = static_cast<uint8_t>(rand2);
    hasSignatureNonce_ = true;
}

Error Interest::encodeInterestSignatureInfo(TlvEncoder& encoder) const {
    uint8_t sigInfoBuf[256];
    TlvEncoder sigInfoEncoder(sigInfoBuf, sizeof(sigInfoBuf));

    // SignatureType
    sigInfoEncoder.writeTlvNonNegativeInteger(tlv::SignatureType,
                                              static_cast<uint8_t>(signatureType_));

    // KeyLocator (optional)
    if (hasKeyLocator_) {
        uint8_t keyLocBuf[NAME_MAX_LENGTH + 4];
        TlvEncoder keyLocEncoder(keyLocBuf, sizeof(keyLocBuf));
        size_t nameLen = 0;
        Error err = keyLocator_.encode(keyLocEncoder.current(), keyLocEncoder.remaining(), nameLen);
        if (err != Error::Success) {
            return err;
        }
        keyLocEncoder.setPosition(keyLocEncoder.position() + nameLen);
        sigInfoEncoder.writeTlv(tlv::KeyLocator, keyLocBuf, keyLocEncoder.size());
    }

    // SignatureNonce (replay attack protection)
    if (hasSignatureNonce_) {
        sigInfoEncoder.writeTlv(tlv::SignatureNonce, signatureNonce_, SIGNATURE_NONCE_SIZE);
    }

    // SignatureTime (optional)
    if (signatureTime_) {
        sigInfoEncoder.writeTlvNonNegativeInteger(tlv::SignatureTime, *signatureTime_);
    }

    // SignatureSeqNum (optional)
    if (signatureSeqNum_) {
        sigInfoEncoder.writeTlvNonNegativeInteger(tlv::SignatureSeqNum, *signatureSeqNum_);
    }

    return encoder.writeTlv(tlv::InterestSignatureInfo, sigInfoBuf, sigInfoEncoder.size());
}

Error Interest::encodeSignedPortion(uint8_t* buf, size_t bufSize, size_t& encodedLen) const {
    TlvEncoder encoder(buf, bufSize);

    // Name
    size_t nameLen = 0;
    Error err = name_.encode(encoder.current(), encoder.remaining(), nameLen);
    if (err != Error::Success) {
        return err;
    }
    encoder.setPosition(encoder.position() + nameLen);

    // ApplicationParameters (required for signed Interest, may be empty)
    err = encoder.writeTlv(tlv::ApplicationParameters, appParams_, appParamsLen_);
    if (err != Error::Success) {
        return err;
    }

    // InterestSignatureInfo
    err = encodeInterestSignatureInfo(encoder);
    if (err != Error::Success) {
        return err;
    }

    encodedLen = encoder.size();
    return Error::Success;
}

Error Interest::signWithDigestSha256() {
    signatureType_ = SignatureType::DigestSha256;
    generateSignatureNonce();
    signatureTime_ = currentTimeMs();

    // Encode the signed portion
    uint8_t signedBuf[PACKET_MAX_SIZE];
    size_t signedLen = 0;
    Error err = encodeSignedPortion(signedBuf, sizeof(signedBuf), signedLen);
    if (err != Error::Success) {
        return err;
    }

    // Compute SHA-256 digest
    err = crypto::sha256(signedBuf, signedLen, signatureValue_.data());
    if (err != Error::Success) {
        return err;
    }

    signatureSize_ = SHA256_DIGEST_SIZE;
    return Error::Success;
}

Error Interest::signWithHmac(const uint8_t* key, size_t keyLen) {
    if (key == nullptr || keyLen == 0) {
        return Error::InvalidParam;
    }

    signatureType_ = SignatureType::SignatureHmacWithSha256;
    generateSignatureNonce();
    signatureTime_ = currentTimeMs();

    // Encode the signed portion
    uint8_t signedBuf[PACKET_MAX_SIZE];
    size_t signedLen = 0;
    Error err = encodeSignedPortion(signedBuf, sizeof(signedBuf), signedLen);
    if (err != Error::Success) {
        return err;
    }

    // Compute HMAC-SHA256
    err = crypto::hmacSha256(key, keyLen, signedBuf, signedLen, signatureValue_.data());
    if (err != Error::Success) {
        return err;
    }

    signatureSize_ = HMAC_SHA256_SIZE;
    return Error::Success;
}

bool Interest::verifyDigestSha256() const {
    if (signatureType_ != SignatureType::DigestSha256) {
        return false;
    }
    if (signatureSize_ != SHA256_DIGEST_SIZE) {
        return false;
    }

    // Encode the signed portion
    uint8_t signedBuf[PACKET_MAX_SIZE];
    size_t signedLen = 0;
    Error err = encodeSignedPortion(signedBuf, sizeof(signedBuf), signedLen);
    if (err != Error::Success) {
        return false;
    }

    // Compute SHA-256 digest
    uint8_t computed[SHA256_DIGEST_SIZE];
    err = crypto::sha256(signedBuf, signedLen, computed);
    if (err != Error::Success) {
        return false;
    }

    // Constant-time comparison
    return crypto::constantTimeCompare(computed, signatureValue_.data(), SHA256_DIGEST_SIZE);
}

bool Interest::verifyHmac(const uint8_t* key, size_t keyLen) const {
    if (key == nullptr || keyLen == 0) {
        return false;
    }
    if (signatureType_ != SignatureType::SignatureHmacWithSha256) {
        return false;
    }
    if (signatureSize_ != HMAC_SHA256_SIZE) {
        return false;
    }

    // Encode the signed portion
    uint8_t signedBuf[PACKET_MAX_SIZE];
    size_t signedLen = 0;
    Error err = encodeSignedPortion(signedBuf, sizeof(signedBuf), signedLen);
    if (err != Error::Success) {
        return false;
    }

    // Compute HMAC-SHA256
    uint8_t computed[HMAC_SHA256_SIZE];
    err = crypto::hmacSha256(key, keyLen, signedBuf, signedLen, computed);
    if (err != Error::Success) {
        return false;
    }

    // Constant-time comparison
    return crypto::constantTimeCompare(computed, signatureValue_.data(), HMAC_SHA256_SIZE);
}

Error Interest::signWithEcdsa(const uint8_t* privKey) {
    if (privKey == nullptr) {
        return Error::InvalidParam;
    }

    signatureType_ = SignatureType::SignatureSha256WithEcdsa;
    generateSignatureNonce();
    signatureTime_ = currentTimeMs();

    // Encode the signed portion
    uint8_t signedBuf[PACKET_MAX_SIZE];
    size_t signedLen = 0;
    Error err = encodeSignedPortion(signedBuf, sizeof(signedBuf), signedLen);
    if (err != Error::Success) {
        return err;
    }

    // Generate ECDSA signature
    err = crypto::ecdsaP256Sign(privKey, signedBuf, signedLen, signatureValue_.data(),
                                &signatureSize_);
    return err;
}

bool Interest::verifyEcdsa(const uint8_t* pubKey) const {
    if (pubKey == nullptr) {
        return false;
    }
    if (signatureType_ != SignatureType::SignatureSha256WithEcdsa) {
        return false;
    }
    if (signatureSize_ == 0 || signatureSize_ > ECDSA_P256_SIG_MAX_SIZE) {
        return false;
    }

    // Encode the signed portion
    uint8_t signedBuf[PACKET_MAX_SIZE];
    size_t signedLen = 0;
    Error err = encodeSignedPortion(signedBuf, sizeof(signedBuf), signedLen);
    if (err != Error::Success) {
        return false;
    }

    // Verify ECDSA signature
    return crypto::ecdsaP256Verify(pubKey, signedBuf, signedLen, signatureValue_.data(),
                                   signatureSize_);
}

Error Interest::encode(uint8_t* buf, size_t bufSize, size_t& encodedLen) const {
    // Encode Interest contents into a temporary buffer
    uint8_t valueBuf[PACKET_MAX_SIZE];
    TlvEncoder valueEncoder(valueBuf, sizeof(valueBuf));

    // Name (required)
    size_t nameLen = 0;
    Error err = name_.encode(valueEncoder.current(), valueEncoder.remaining(), nameLen);
    if (err != Error::Success) {
        return err;
    }
    valueEncoder.setPosition(valueEncoder.position() + nameLen);

    // CanBePrefix (empty TLV)
    if (canBePrefix_) {
        err = valueEncoder.writeType(tlv::CanBePrefix);
        if (err != Error::Success) {
            return err;
        }
        err = valueEncoder.writeLength(0);
        if (err != Error::Success) {
            return err;
        }
    }

    // MustBeFresh (empty TLV)
    if (mustBeFresh_) {
        err = valueEncoder.writeType(tlv::MustBeFresh);
        if (err != Error::Success) {
            return err;
        }
        err = valueEncoder.writeLength(0);
        if (err != Error::Success) {
            return err;
        }
    }

    // ForwardingHint (list of Names)
    if (fwHintCount_ > 0) {
        // Encode list of Names within ForwardingHint
        uint8_t fwHintBuf[512];
        TlvEncoder fwHintEncoder(fwHintBuf, sizeof(fwHintBuf));

        for (size_t i = 0; i < fwHintCount_; ++i) {
            size_t hintNameLen = 0;
            err =
                fwHints_[i].encode(fwHintEncoder.current(), fwHintEncoder.remaining(), hintNameLen);
            if (err != Error::Success) {
                return err;
            }
            fwHintEncoder.setPosition(fwHintEncoder.position() + hintNameLen);
        }

        err = valueEncoder.writeTlv(tlv::ForwardingHint, fwHintBuf, fwHintEncoder.size());
        if (err != Error::Success) {
            return err;
        }
    }

    // Nonce (fixed 4 bytes)
    if (nonce_) {
        err = valueEncoder.writeType(tlv::Nonce);
        if (err != Error::Success) {
            return err;
        }
        err = valueEncoder.writeLength(4);
        if (err != Error::Success) {
            return err;
        }
        // Write in big-endian
        uint8_t nonceBytes[4] = {static_cast<uint8_t>(*nonce_ >> 24),
                                 static_cast<uint8_t>(*nonce_ >> 16),
                                 static_cast<uint8_t>(*nonce_ >> 8), static_cast<uint8_t>(*nonce_)};
        err = valueEncoder.writeBytes(nonceBytes, 4);
        if (err != Error::Success) {
            return err;
        }
    }

    // InterestLifetime (only if non-default)
    if (lifetime_ != INTEREST_DEFAULT_LIFETIME_MS) {
        err = valueEncoder.writeTlvNonNegativeInteger(tlv::InterestLifetime, lifetime_);
        if (err != Error::Success) {
            return err;
        }
    }

    // HopLimit
    if (hopLimit_) {
        err = valueEncoder.writeType(tlv::HopLimit);
        if (err != Error::Success) {
            return err;
        }
        err = valueEncoder.writeLength(1);
        if (err != Error::Success) {
            return err;
        }
        const uint8_t hopLimitValue = *hopLimit_;
        err = valueEncoder.writeBytes(&hopLimitValue, 1);
        if (err != Error::Success) {
            return err;
        }
    }

    // ApplicationParameters (required when signed)
    if (appParamsLen_ > 0 || signatureSize_ > 0) {
        err = valueEncoder.writeTlv(tlv::ApplicationParameters, appParams_, appParamsLen_);
        if (err != Error::Success) {
            return err;
        }
    }

    // If signed, append InterestSignatureInfo and InterestSignatureValue
    if (signatureSize_ > 0) {
        // InterestSignatureInfo
        err = encodeInterestSignatureInfo(valueEncoder);
        if (err != Error::Success) {
            return err;
        }

        // InterestSignatureValue
        err = valueEncoder.writeTlv(tlv::InterestSignatureValue, signatureValue_.data(),
                                    signatureSize_);
        if (err != Error::Success) {
            return err;
        }
    }

    // Write Interest TLV header
    const size_t valueLen = valueEncoder.size();
    const size_t headerSize = varNumberSize(tlv::Interest) + varNumberSize(valueLen);
    const size_t totalSize = headerSize + valueLen;

    if (bufSize < totalSize) {
        return Error::BufferTooSmall;
    }

    TlvEncoder encoder(buf, bufSize);
    err = encoder.writeType(tlv::Interest);
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

Error Interest::parseSignatureInfo(TlvDecoder& decoder, size_t elemLen, Interest& interest) {
    const size_t sigInfoEnd = decoder.position() + elemLen;
    while (decoder.position() < sigInfoEnd) {
        auto sigInfoElemHeader = decoder.readTlvHeader();
        if (!sigInfoElemHeader.ok()) {
            return sigInfoElemHeader.error;
        }

        switch (sigInfoElemHeader.value.type) {
            case tlv::SignatureType: {
                auto stResult = decoder.readNonNegativeInteger(sigInfoElemHeader.value.length);
                if (!stResult.ok()) {
                    return stResult.error;
                }
                interest.signatureType_ = static_cast<SignatureType>(stResult.value);
                break;
            }

            case tlv::SignatureNonce: {
                if (sigInfoElemHeader.value.length > Interest::SIGNATURE_NONCE_SIZE) {
                    decoder.skip(sigInfoElemHeader.value.length);
                } else {
                    auto err =
                        decoder.readBytes(interest.signatureNonce_, sigInfoElemHeader.value.length);
                    if (err != Error::Success) {
                        return err;
                    }
                    interest.hasSignatureNonce_ = true;
                }
                break;
            }

            case tlv::SignatureTime: {
                auto stResult = decoder.readNonNegativeInteger(sigInfoElemHeader.value.length);
                if (!stResult.ok()) {
                    return stResult.error;
                }
                interest.signatureTime_ = stResult.value;
                break;
            }

            case tlv::SignatureSeqNum: {
                auto seqResult = decoder.readNonNegativeInteger(sigInfoElemHeader.value.length);
                if (!seqResult.ok()) {
                    return seqResult.error;
                }
                interest.signatureSeqNum_ = seqResult.value;
                break;
            }

            case tlv::KeyLocator: {
                const size_t keyLocEnd = decoder.position() + sigInfoElemHeader.value.length;
                if (decoder.position() < keyLocEnd) {
                    size_t bytesRead = 0;
                    auto nameResult =
                        Name::fromWire(decoder.current(), decoder.remaining(), &bytesRead);
                    if (nameResult.ok()) {
                        interest.keyLocator_ = nameResult.value;
                        interest.hasKeyLocator_ = true;
                    }
                    decoder.setPosition(keyLocEnd);
                }
                break;
            }

            default:
                decoder.skip(sigInfoElemHeader.value.length);
                break;
        }
    }
    return Error::Success;
}

Result<Interest> Interest::fromWire(const uint8_t* buf, size_t len) {
    Interest interest;
    TlvDecoder decoder(buf, len);

    // Interest TLV header
    auto headerResult = decoder.readTlvHeader();
    if (!headerResult.ok()) {
        return {.value = Interest{}, .error = headerResult.error};
    }

    if (headerResult.value.type != tlv::Interest) {
        return {.value = Interest{}, .error = Error::InvalidPacket};
    }

    const size_t interestValueLen = headerResult.value.length;
    const size_t interestValueEnd = decoder.position() + interestValueLen;

    if (decoder.remaining() < interestValueLen) {
        return {.value = Interest{}, .error = Error::DecodeFailed};
    }

    // Parse TLVs within the Interest
    bool hasName = false;

    while (decoder.position() < interestValueEnd) {
        const size_t elementStart = decoder.position();

        auto elemHeader = decoder.readTlvHeader();
        if (!elemHeader.ok()) {
            return {.value = Interest{}, .error = elemHeader.error};
        }

        const uint32_t elemType = elemHeader.value.type;
        const size_t elemLen = elemHeader.value.length;

        if (decoder.remaining() < elemLen) {
            return {.value = Interest{}, .error = Error::DecodeFailed};
        }

        switch (elemType) {
            case tlv::Name: {
                // Re-decode Name (including header)
                decoder.setPosition(elementStart);
                size_t bytesRead = 0;
                auto nameResult =
                    Name::fromWire(decoder.current(), decoder.remaining(), &bytesRead);
                if (!nameResult.ok()) {
                    return {.value = Interest{}, .error = nameResult.error};
                }
                interest.name_ = nameResult.value;
                decoder.skip(bytesRead);
                hasName = true;
                break;
            }

            case tlv::Nonce: {
                if (elemLen != 4) {
                    return {.value = Interest{}, .error = Error::DecodeFailed};
                }
                auto nonceResult = decoder.readNonNegativeInteger(4);
                if (!nonceResult.ok()) {
                    return {.value = Interest{}, .error = nonceResult.error};
                }
                interest.nonce_ = static_cast<uint32_t>(nonceResult.value);
                break;
            }

            case tlv::InterestLifetime: {
                auto lifetimeResult = decoder.readNonNegativeInteger(elemLen);
                if (!lifetimeResult.ok()) {
                    return {.value = Interest{}, .error = lifetimeResult.error};
                }
                interest.lifetime_ = static_cast<uint32_t>(lifetimeResult.value);
                break;
            }

            case tlv::HopLimit: {
                if (elemLen != 1) {
                    return {.value = Interest{}, .error = Error::DecodeFailed};
                }
                auto hopLimitResult = decoder.readNonNegativeInteger(1);
                if (!hopLimitResult.ok()) {
                    return {.value = Interest{}, .error = hopLimitResult.error};
                }
                interest.hopLimit_ = static_cast<uint8_t>(hopLimitResult.value);
                break;
            }

            case tlv::CanBePrefix: {
                // Empty TLV
                interest.canBePrefix_ = true;
                decoder.skip(elemLen);
                break;
            }

            case tlv::MustBeFresh: {
                // Empty TLV
                interest.mustBeFresh_ = true;
                decoder.skip(elemLen);
                break;
            }

            case tlv::ForwardingHint: {
                // Decode list of Names within ForwardingHint
                const size_t fwHintEnd = decoder.position() + elemLen;
                while (decoder.position() < fwHintEnd) {
                    size_t bytesRead = 0;
                    auto nameResult =
                        Name::fromWire(decoder.current(), decoder.remaining(), &bytesRead);
                    if (!nameResult.ok()) {
                        return {.value = Interest{}, .error = nameResult.error};
                    }
                    if (interest.fwHintCount_ < Interest::FW_HINT_MAX_COUNT) {
                        interest.fwHints_[interest.fwHintCount_++] = nameResult.value;
                    }
                    decoder.skip(bytesRead);
                }
                break;
            }

            case tlv::ApplicationParameters: {
                if (elemLen > Interest::APP_PARAMS_MAX_SIZE) {
                    return {.value = Interest{}, .error = Error::BufferTooSmall};
                }
                auto err = decoder.readBytes(interest.appParams_, elemLen);
                if (err != Error::Success) {
                    return {.value = Interest{}, .error = err};
                }
                interest.appParamsLen_ = elemLen;
                break;
            }

            case tlv::InterestSignatureInfo: {
                const Error err = parseSignatureInfo(decoder, elemLen, interest);
                if (err != Error::Success) {
                    return {.value = Interest{}, .error = err};
                }
                break;
            }

            case tlv::InterestSignatureValue: {
                if (elemLen > SIGNATURE_MAX_SIZE) {
                    return {.value = Interest{}, .error = Error::BufferTooSmall};
                }
                auto err = decoder.readBytes(interest.signatureValue_.data(), elemLen);
                if (err != Error::Success) {
                    return {.value = Interest{}, .error = err};
                }
                interest.signatureSize_ = elemLen;
                break;
            }

            default:
                // Skip unknown TLVs
                decoder.skip(elemLen);
                break;
        }
    }

    if (!hasName) {
        return {.value = Interest{}, .error = Error::InvalidPacket};
    }

    return {.value = interest, .error = Error::Success};
}

}  // namespace ndn
