#include "ndn/data.hpp"

#include "ndn/crypto.hpp"
#include "ndn/tlv.hpp"

#include <cstring>

namespace ndn {

Data::Data(const Name& name) : name_(name) {}

Data& Data::setName(const Name& name) {
    name_ = name;
    return *this;
}

Error Data::setName(std::string_view uri) {
    auto result = Name::fromUri(uri);
    if (!result.ok()) {
        return result.error;
    }
    name_ = result.value;
    return Error::Success;
}

Error Data::setContent(const uint8_t* data, size_t size) {
    if (size > DATA_MAX_CONTENT_SIZE) {
        return Error::BufferTooSmall;
    }
    std::memcpy(content_.data(), data, size);
    contentSize_ = size;
    return Error::Success;
}

Error Data::setContent(std::string_view str) {
    return setContent(reinterpret_cast<const uint8_t*>(str.data()), str.size());
}

Data& Data::setFreshnessPeriod(uint32_t periodMs) {
    freshnessPeriod_ = periodMs;
    return *this;
}

Data& Data::setFinalBlockId(uint64_t segmentNum) {
    finalBlockId_ = segmentNum;
    return *this;
}

Data& Data::clearFinalBlockId() {
    finalBlockId_.reset();
    return *this;
}

Data& Data::setContentType(ContentType type) {
    contentType_ = type;
    return *this;
}

Data& Data::setSignatureType(SignatureType type) {
    signatureType_ = type;
    return *this;
}

Data& Data::setKeyLocator(const Name& name) {
    keyLocator_ = name;
    hasKeyLocator_ = true;
    return *this;
}

Data& Data::clearKeyLocator() {
    keyLocator_ = Name{};
    hasKeyLocator_ = false;
    return *this;
}

Error Data::encodeSignedPortion(uint8_t* buf, size_t bufSize, size_t& encodedLen) const {
    TlvEncoder encoder(buf, bufSize);

    // Name (required)
    size_t nameLen = 0;
    Error err = name_.encode(encoder.current(), encoder.remaining(), nameLen);
    if (err != Error::Success) {
        return err;
    }
    encoder.setPosition(encoder.position() + nameLen);

    // MetaInfo (if ContentType, FreshnessPeriod, or FinalBlockId is present)
    if (contentType_ != ContentType::Blob || freshnessPeriod_ || finalBlockId_) {
        uint8_t metaInfoBuf[48];
        TlvEncoder metaEncoder(metaInfoBuf, sizeof(metaInfoBuf));

        // ContentType (only if not Blob)
        if (contentType_ != ContentType::Blob) {
            err = metaEncoder.writeTlvNonNegativeInteger(tlv::ContentType,
                                                         static_cast<uint8_t>(contentType_));
            if (err != Error::Success) {
                return err;
            }
        }

        // FreshnessPeriod
        if (freshnessPeriod_) {
            err = metaEncoder.writeTlvNonNegativeInteger(tlv::FreshnessPeriod, *freshnessPeriod_);
            if (err != Error::Success) {
                return err;
            }
        }

        // FinalBlockId (NameComponent format)
        if (finalBlockId_) {
            // Encode segment number as non-negative integer, wrapped in GenericNameComponent
            uint8_t segNumBuf[9];
            TlvEncoder segNumEncoder(segNumBuf, sizeof(segNumBuf));
            segNumEncoder.writeNonNegativeInteger(*finalBlockId_);

            // Store GenericNameComponent TLV inside FinalBlockId TLV
            uint8_t compBuf[16];
            TlvEncoder compEncoder(compBuf, sizeof(compBuf));
            compEncoder.writeTlv(tlv::GenericNameComponent, segNumBuf, segNumEncoder.size());

            err = metaEncoder.writeTlv(tlv::FinalBlockId, compBuf, compEncoder.size());
            if (err != Error::Success) {
                return err;
            }
        }

        err = encoder.writeTlv(tlv::MetaInfo, metaInfoBuf, metaEncoder.size());
        if (err != Error::Success) {
            return err;
        }
    }

    // Content
    if (contentSize_ > 0) {
        err = encoder.writeTlv(tlv::Content, content_.data(), contentSize_);
        if (err != Error::Success) {
            return err;
        }
    }

    // SignatureInfo (SignatureType + KeyLocator)
    uint8_t sigInfoBuf[NAME_MAX_LENGTH + 16];
    TlvEncoder sigInfoEncoder(sigInfoBuf, sizeof(sigInfoBuf));
    sigInfoEncoder.writeTlvNonNegativeInteger(tlv::SignatureType,
                                              static_cast<uint8_t>(signatureType_));

    // KeyLocator (optional)
    if (hasKeyLocator_) {
        uint8_t keyLocBuf[NAME_MAX_LENGTH + 4];
        TlvEncoder keyLocEncoder(keyLocBuf, sizeof(keyLocBuf));
        size_t keyLocNameLen = 0;
        err = keyLocator_.encode(keyLocEncoder.current(), keyLocEncoder.remaining(), keyLocNameLen);
        if (err != Error::Success) {
            return err;
        }
        keyLocEncoder.setPosition(keyLocEncoder.position() + keyLocNameLen);
        sigInfoEncoder.writeTlv(tlv::KeyLocator, keyLocBuf, keyLocEncoder.size());
    }

    err = encoder.writeTlv(tlv::SignatureInfo, sigInfoBuf, sigInfoEncoder.size());
    if (err != Error::Success) {
        return err;
    }

    encodedLen = encoder.size();
    return Error::Success;
}

Error Data::signWithDigestSha256() {
    signatureType_ = SignatureType::DigestSha256;

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

Error Data::signWithHmac(const uint8_t* key, size_t keyLen) {
    if (key == nullptr || keyLen == 0) {
        return Error::InvalidParam;
    }

    signatureType_ = SignatureType::SignatureHmacWithSha256;

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

bool Data::verifyDigestSha256() const {
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

bool Data::verifyHmac(const uint8_t* key, size_t keyLen) const {
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

Error Data::signWithEcdsa(const uint8_t* privKey) {
    if (privKey == nullptr) {
        return Error::InvalidParam;
    }

    signatureType_ = SignatureType::SignatureSha256WithEcdsa;

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

bool Data::verifyEcdsa(const uint8_t* pubKey) const {
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

Error Data::encode(uint8_t* buf, size_t bufSize, size_t& encodedLen) const {
    uint8_t valueBuf[PACKET_MAX_SIZE];
    TlvEncoder valueEncoder(valueBuf, sizeof(valueBuf));

    // Encode signed portion (Name + MetaInfo + Content + SignatureInfo)
    size_t signedLen = 0;
    Error err = encodeSignedPortion(valueEncoder.current(), valueEncoder.remaining(), signedLen);
    if (err != Error::Success) {
        return err;
    }
    valueEncoder.setPosition(valueEncoder.position() + signedLen);

    // SignatureValue
    err = valueEncoder.writeTlv(tlv::SignatureValue, signatureValue_.data(), signatureSize_);
    if (err != Error::Success) {
        return err;
    }

    // Write Data TLV header
    const size_t valueLen = valueEncoder.size();
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

Result<Data> Data::fromWire(const uint8_t* buf, size_t len) {
    Data data;
    TlvDecoder decoder(buf, len);

    // Data TLV header
    auto headerResult = decoder.readTlvHeader();
    if (!headerResult.ok()) {
        return {.value = Data{}, .error = headerResult.error};
    }

    if (headerResult.value.type != tlv::Data) {
        return {.value = Data{}, .error = Error::InvalidPacket};
    }

    const size_t dataValueLen = headerResult.value.length;
    const size_t dataValueEnd = decoder.position() + dataValueLen;

    if (decoder.remaining() < dataValueLen) {
        return {.value = Data{}, .error = Error::DecodeFailed};
    }

    // Parse TLVs within the Data
    bool hasName = false;

    while (decoder.position() < dataValueEnd) {
        const size_t elementStart = decoder.position();

        auto elemHeader = decoder.readTlvHeader();
        if (!elemHeader.ok()) {
            return {.value = Data{}, .error = elemHeader.error};
        }

        const uint32_t elemType = elemHeader.value.type;
        const size_t elemLen = elemHeader.value.length;

        if (decoder.remaining() < elemLen) {
            return {.value = Data{}, .error = Error::DecodeFailed};
        }

        switch (elemType) {
            case tlv::Name: {
                decoder.setPosition(elementStart);
                size_t bytesRead = 0;
                auto nameResult =
                    Name::fromWire(decoder.current(), decoder.remaining(), &bytesRead);
                if (!nameResult.ok()) {
                    return {.value = Data{}, .error = nameResult.error};
                }
                data.name_ = nameResult.value;
                decoder.skip(bytesRead);
                hasName = true;
                break;
            }

            case tlv::MetaInfo: {
                // Parse fields within MetaInfo
                const size_t metaEnd = decoder.position() + elemLen;
                while (decoder.position() < metaEnd) {
                    auto metaElemHeader = decoder.readTlvHeader();
                    if (!metaElemHeader.ok()) {
                        return {.value = Data{}, .error = metaElemHeader.error};
                    }

                    if (metaElemHeader.value.type == tlv::ContentType) {
                        auto ctResult = decoder.readNonNegativeInteger(metaElemHeader.value.length);
                        if (!ctResult.ok()) {
                            return {.value = Data{}, .error = ctResult.error};
                        }
                        data.contentType_ = static_cast<ContentType>(ctResult.value);
                    } else if (metaElemHeader.value.type == tlv::FreshnessPeriod) {
                        auto fpResult = decoder.readNonNegativeInteger(metaElemHeader.value.length);
                        if (!fpResult.ok()) {
                            return {.value = Data{}, .error = fpResult.error};
                        }
                        data.freshnessPeriod_ = static_cast<uint32_t>(fpResult.value);
                    } else if (metaElemHeader.value.type == tlv::FinalBlockId) {
                        // Parse NameComponent within FinalBlockId
                        auto compHeader = decoder.readTlvHeader();
                        if (!compHeader.ok()) {
                            return {.value = Data{}, .error = compHeader.error};
                        }
                        // Read the value within NameComponent as a non-negative integer
                        auto segNumResult = decoder.readNonNegativeInteger(compHeader.value.length);
                        if (!segNumResult.ok()) {
                            return {.value = Data{}, .error = segNumResult.error};
                        }
                        data.finalBlockId_ = segNumResult.value;
                    } else {
                        decoder.skip(metaElemHeader.value.length);
                    }
                }
                break;
            }

            case tlv::Content: {
                if (elemLen > DATA_MAX_CONTENT_SIZE) {
                    return {.value = Data{}, .error = Error::BufferTooSmall};
                }
                const Error err = decoder.readBytes(data.content_.data(), elemLen);
                if (err != Error::Success) {
                    return {.value = Data{}, .error = err};
                }
                data.contentSize_ = elemLen;
                break;
            }

            case tlv::SignatureInfo: {
                // Parse fields within SignatureInfo
                const size_t sigInfoEnd = decoder.position() + elemLen;
                while (decoder.position() < sigInfoEnd) {
                    auto sigInfoElemHeader = decoder.readTlvHeader();
                    if (!sigInfoElemHeader.ok()) {
                        return {.value = Data{}, .error = sigInfoElemHeader.error};
                    }

                    if (sigInfoElemHeader.value.type == tlv::SignatureType) {
                        auto stResult =
                            decoder.readNonNegativeInteger(sigInfoElemHeader.value.length);
                        if (!stResult.ok()) {
                            return {.value = Data{}, .error = stResult.error};
                        }
                        data.signatureType_ = static_cast<SignatureType>(stResult.value);
                    } else if (sigInfoElemHeader.value.type == tlv::KeyLocator) {
                        // Decode Name within KeyLocator
                        const size_t keyLocEnd =
                            decoder.position() + sigInfoElemHeader.value.length;
                        if (decoder.position() < keyLocEnd) {
                            size_t bytesRead = 0;
                            auto nameResult =
                                Name::fromWire(decoder.current(), decoder.remaining(), &bytesRead);
                            if (nameResult.ok()) {
                                data.keyLocator_ = nameResult.value;
                                data.hasKeyLocator_ = true;
                            }
                            decoder.setPosition(keyLocEnd);
                        }
                    } else {
                        // Ignore others
                        decoder.skip(sigInfoElemHeader.value.length);
                    }
                }
                break;
            }

            case tlv::SignatureValue: {
                if (elemLen > SIGNATURE_MAX_SIZE) {
                    return {.value = Data{}, .error = Error::BufferTooSmall};
                }
                const Error err = decoder.readBytes(data.signatureValue_.data(), elemLen);
                if (err != Error::Success) {
                    return {.value = Data{}, .error = err};
                }
                data.signatureSize_ = elemLen;
                break;
            }

            default:
                // Ignore unknown TLVs
                decoder.skip(elemLen);
                break;
        }
    }

    if (!hasName) {
        return {.value = Data{}, .error = Error::InvalidPacket};
    }

    return {.value = data, .error = Error::Success};
}

}  // namespace ndn
