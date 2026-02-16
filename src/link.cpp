#include "ndn/link.hpp"

#include "ndn/tlv.hpp"

namespace ndn {

Link::Link(const Name& name) : name_(name) {}

Link& Link::setName(const Name& name) {
    name_ = name;
    return *this;
}

Error Link::setName(std::string_view uri) {
    auto result = Name::fromUri(uri);
    if (!result.ok()) {
        return result.error;
    }
    name_ = result.value;
    return Error::Success;
}

Error Link::addDelegation(const Name& delegation) {
    if (delegationCount_ >= LINK_MAX_DELEGATIONS) {
        return Error::Full;
    }

    // Check for duplicates
    for (size_t i = 0; i < delegationCount_; ++i) {
        if (delegations_[i].equals(delegation)) {
            return Error::InvalidParam;
        }
    }

    delegations_[delegationCount_++] = delegation;
    return Error::Success;
}

Error Link::addDelegation(std::string_view uri) {
    auto result = Name::fromUri(uri);
    if (!result.ok()) {
        return result.error;
    }
    return addDelegation(result.value);
}

const Name* Link::delegation(size_t index) const {
    if (index >= delegationCount_) {
        return nullptr;
    }
    return &delegations_[index];
}

void Link::clearDelegations() {
    delegationCount_ = 0;
}

bool Link::hasDelegation(const Name& name) const {
    for (size_t i = 0; i < delegationCount_; ++i) {
        if (delegations_[i].equals(name)) {
            return true;
        }
    }
    return false;
}

Error Link::toData(Data& data) const {
    data.setName(name_);
    data.setContentType(ContentType::Link);

    if (delegationCount_ == 0) {
        // At least one delegation is required
        return Error::InvalidParam;
    }

    // Encode delegations (list of Names) into Content
    uint8_t contentBuf[DATA_MAX_CONTENT_SIZE];
    TlvEncoder encoder(contentBuf, sizeof(contentBuf));

    for (size_t i = 0; i < delegationCount_; ++i) {
        size_t nameLen = 0;
        const Error err = delegations_[i].encode(encoder.current(), encoder.remaining(), nameLen);
        if (err != Error::Success) {
            return err;
        }
        encoder.setPosition(encoder.position() + nameLen);
    }

    const Error err = data.setContent(contentBuf, encoder.size());
    if (err != Error::Success) {
        return err;
    }

    return Error::Success;
}

Result<Link> Link::fromData(const Data& data) {
    if (data.contentType() != ContentType::Link) {
        return {.value = Link{}, .error = Error::InvalidPacket};
    }

    if (!data.hasContent()) {
        return {.value = Link{}, .error = Error::InvalidPacket};
    }

    Link link;
    link.name_ = data.name();

    // Decode list of Names from Content
    TlvDecoder decoder(data.content(), data.contentSize());

    while (decoder.hasMore()) {
        size_t bytesRead = 0;
        auto nameResult = Name::fromWire(decoder.current(), decoder.remaining(), &bytesRead);
        if (!nameResult.ok()) {
            return {.value = Link{}, .error = nameResult.error};
        }

        const Error err = link.addDelegation(nameResult.value);
        if (err != Error::Success) {
            return {.value = Link{}, .error = err};
        }

        decoder.skip(bytesRead);
    }

    if (link.delegationCount_ == 0) {
        return {.value = Link{}, .error = Error::InvalidPacket};
    }

    return {.value = link, .error = Error::Success};
}

}  // namespace ndn
