# API Reference

This document defines the C++ API for the NDN protocol stack for ESP32.
All header files are documented in Doxygen format.

## Implementation Status

| Module     | Header | Impl | Unit Tests | Integration | On-device | Doxygen |
|------------|--------|------|------------|-------------|-----------|---------|
| Common     | Done   | Done | -          | -           | -         | Done    |
| TLV        | Done   | Done | Done (15)  | -           | Done      | Done    |
| Name       | Done   | Done | Done (16)  | -           | Done      | Done    |
| Interest   | Done   | Done | Done (17)  | -           | Done      | Done    |
| Data       | Done   | Done | Done (19)  | -           | Done      | Done    |
| Signature  | Done   | Done | -          | -           | -         | Done    |
| Crypto     | Done   | Done | -          | -           | Done      | Done    |
| Certificate| Done   | Done | -          | -           | Done      | Done    |
| Link       | Done   | Done | -          | -           | Done      | Done    |
| PIT        | Done   | Done | Done (21)  | -           | Done      | -       |
| CS         | Done   | Done | Done (24)  | -           | Done      | -       |
| FIB        | Done   | Done | Done (24)  | -           | Done      | -       |
| Face       | Done   | Done | -          | -           | -         | Done    |
| EspNowFace | Done   | Done | Done (15)  | -           | Done      | Done    |
| Forwarder  | Done   | Done | Done (32)  | Done        | Done      | -       |
| API        | Done   | Done | -          | -           | Done      | -       |

**Total tests: 214** (unit: 214)

**On-device test results:**

- ESP-NOW Ping (2 nodes): RTT 10-11 ms, packet loss rate 2.9%
- CS cache hit (3 nodes): 20 cache hits
- Multi-hop forwarding (3 nodes): RTT 50-60 ms, virtual topology via multiple MAC filters
- Cache effect measurement (3 nodes): ~48% RTT reduction, 24 cache hits

---

## 1. Namespace and Fundamental Types

### 1.1 common.hpp

Common definitions used throughout the NDN library, including error codes, constants,
the `Result<T>` type, and utility functions.

```cpp
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace ndn {

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

enum class Error : uint8_t {
    Success = 0,        ///< Operation succeeded
    InvalidParam,       ///< Invalid parameter
    BufferTooSmall,     ///< Buffer too small
    DecodeFailed,       ///< Decoding failed
    NotFound,           ///< Entry not found
    NoMemory,           ///< Out of memory
    Full,               ///< Table is full
    Timeout,            ///< Timed out
    SendFailed,         ///< Send failed
    InvalidPacket,      ///< Invalid packet
    NameTooLong,        ///< Name exceeds maximum length
    TooManyComponents,  ///< Too many Name components
};

/// Convert an error code to a human-readable string.
constexpr const char* errorToString(Error error);

// ---------------------------------------------------------------------------
// Content type (Data packet MetaInfo)
// ---------------------------------------------------------------------------

enum class ContentType : uint8_t {
    Blob = 0,  ///< Binary data (default)
    Link = 1,  ///< Link Object (list of Names for forwarding hints)
    Key  = 2,  ///< Public key
    Nack = 3,  ///< Network NACK
};

// ---------------------------------------------------------------------------
// Face identifier
// ---------------------------------------------------------------------------

using FaceId = uint16_t;

constexpr FaceId FACE_ID_INVALID = 0;  ///< Invalid Face ID
constexpr FaceId FACE_ID_LOCAL   = 1;  ///< Face ID reserved for local applications

// ---------------------------------------------------------------------------
// Timestamp type
// ---------------------------------------------------------------------------

/// Millisecond timestamp (monotonic, since boot).
using TimeMs = uint64_t;

// ---------------------------------------------------------------------------
// Size constants
// ---------------------------------------------------------------------------

constexpr size_t NAME_MAX_LENGTH       = 128;   ///< Maximum encoded Name length (bytes)
constexpr size_t NAME_MAX_COMPONENTS   = 10;    ///< Maximum number of Name components
constexpr size_t DATA_MAX_CONTENT_SIZE = 1440;  ///< Maximum Data content size (bytes)
constexpr size_t PACKET_MAX_SIZE       = 1470;  ///< Maximum packet size (ESP-NOW v2.0)
constexpr size_t LINK_MAX_DELEGATIONS  = 5;     ///< Maximum delegations in a Link Object

constexpr uint32_t INTEREST_DEFAULT_LIFETIME_MS = 4000;  ///< Default Interest lifetime (ms)

// ---------------------------------------------------------------------------
// Result<T>
// ---------------------------------------------------------------------------

/// Lightweight result type that pairs a value with an error code.
/// Used instead of exceptions.
template <typename T>
struct Result {
    T value;      ///< The result value
    Error error;  ///< Error code

    /// Returns true when the operation succeeded.
    bool ok() const { return error == Error::Success; }

    /// Explicit conversion to bool (true on success).
    explicit operator bool() const { return ok(); }
};

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Return the current monotonic time in milliseconds.
TimeMs currentTimeMs();

/// Generate a random 32-bit nonce value.
uint32_t generateRandomNonce();

}  // namespace ndn
```

---

## 2. Signature Types and Constants

### 2.1 signature.hpp

Defines signature algorithm identifiers and associated size constants.

```cpp
#pragma once

#include <cstddef>
#include <cstdint>

namespace ndn {

// ---------------------------------------------------------------------------
// Signature type enum
// ---------------------------------------------------------------------------

enum class SignatureType : uint8_t {
    DigestSha256             = 0,  ///< SHA-256 digest (integrity only, no key)
    SignatureSha256WithRsa   = 1,  ///< RSA signature (PKCS#1 v1.5)
    SignatureSha256WithEcdsa = 3,  ///< ECDSA signature (P-256)
    SignatureHmacWithSha256  = 4,  ///< HMAC-SHA256 (symmetric key)
    SignatureEd25519         = 5,  ///< Ed25519 signature
};

// ---------------------------------------------------------------------------
// Signature size constants
// ---------------------------------------------------------------------------

constexpr size_t SHA256_DIGEST_SIZE      = 32;   ///< SHA-256 digest size (bytes)
constexpr size_t HMAC_SHA256_SIZE        = 32;   ///< HMAC-SHA256 output size (bytes)
constexpr size_t ECDSA_P256_SIG_MAX_SIZE = 72;   ///< ECDSA P-256 max signature size (DER)
constexpr size_t ED25519_SIG_SIZE        = 64;   ///< Ed25519 signature size (bytes)
constexpr size_t RSA_2048_SIG_SIZE       = 256;  ///< RSA-2048 signature size (bytes)
constexpr size_t SIGNATURE_MAX_SIZE      = 72;   ///< Max signature buffer (ECDSA P-256)

// ---------------------------------------------------------------------------
// Public key size constants
// ---------------------------------------------------------------------------

constexpr size_t ECDSA_P256_PUBKEY_SIZE  = 65;  ///< ECDSA P-256 public key (uncompressed)
constexpr size_t ECDSA_P256_PRIVKEY_SIZE = 32;  ///< ECDSA P-256 private key
constexpr size_t ED25519_PUBKEY_SIZE     = 32;  ///< Ed25519 public key
constexpr size_t ED25519_PRIVKEY_SIZE    = 32;  ///< Ed25519 private key

/// Convert a SignatureType to a human-readable string.
constexpr const char* signatureTypeToString(SignatureType type);

}  // namespace ndn
```

---

## 3. TLV Encoding / Decoding

### 3.1 TLV Type Constants

```cpp
namespace ndn::tlv {

// Packet types
constexpr uint32_t Interest = 0x05;
constexpr uint32_t Data     = 0x06;

// Common fields
constexpr uint32_t Name = 0x07;

// Name components
constexpr uint32_t GenericNameComponent    = 0x08;
constexpr uint32_t ImplicitSha256Digest    = 0x01;
constexpr uint32_t ParametersSha256Digest  = 0x02;

// Interest packet fields
constexpr uint32_t CanBePrefix            = 0x21;
constexpr uint32_t MustBeFresh            = 0x12;
constexpr uint32_t ForwardingHint         = 0x1e;
constexpr uint32_t Nonce                  = 0x0a;
constexpr uint32_t InterestLifetime       = 0x0c;
constexpr uint32_t HopLimit               = 0x22;
constexpr uint32_t ApplicationParameters  = 0x24;

// Data packet fields
constexpr uint32_t MetaInfo       = 0x14;
constexpr uint32_t Content        = 0x15;
constexpr uint32_t SignatureInfo  = 0x16;
constexpr uint32_t SignatureValue = 0x17;

// MetaInfo fields
constexpr uint32_t ContentType    = 0x18;
constexpr uint32_t FreshnessPeriod = 0x19;
constexpr uint32_t FinalBlockId   = 0x1a;

// SignatureInfo sub-fields
constexpr uint32_t SignatureType  = 0x1b;
constexpr uint32_t KeyLocator     = 0x1c;
constexpr uint32_t KeyDigest      = 0x1d;

// Interest signature fields
constexpr uint32_t SignatureNonce          = 0x26;
constexpr uint32_t SignatureTime           = 0x28;
constexpr uint32_t SignatureSeqNum         = 0x2a;
constexpr uint32_t InterestSignatureInfo   = 0x2c;
constexpr uint32_t InterestSignatureValue  = 0x2e;

// Certificate fields
constexpr uint32_t ValidityPeriod = 0xfd;  // 253
constexpr uint32_t NotBefore      = 0xfe;  // 254
constexpr uint32_t NotAfter       = 0xff;  // 255

}  // namespace ndn::tlv
```

### 3.2 TlvEncoder

Writes TLV-encoded data into a caller-provided buffer.

```cpp
class TlvEncoder {
public:
    /// Construct an encoder that writes into the given buffer.
    TlvEncoder(uint8_t* buf, size_t capacity);

    /// Write a VAR-NUMBER (1, 3, 5, or 9 bytes depending on value).
    Error writeVarNumber(uint64_t value);

    /// Write a non-negative integer in big-endian using the minimum number of bytes.
    Error writeNonNegativeInteger(uint64_t value);

    /// Write a TLV Type field.
    Error writeType(uint32_t type);

    /// Write a TLV Length field.
    Error writeLength(size_t length);

    /// Write raw bytes.
    Error writeBytes(const uint8_t* data, size_t len);

    /// Write a complete TLV (Type + Length + Value).
    Error writeTlv(uint32_t type, const uint8_t* value, size_t valueLen);

    /// Write a non-negative integer wrapped in a TLV.
    Error writeTlvNonNegativeInteger(uint32_t type, uint64_t value);

    /// Number of bytes written so far.
    size_t size() const;

    /// Remaining writable bytes.
    size_t remaining() const;

    /// Pointer to the current write position.
    uint8_t* current();

    /// Get the current byte offset.
    size_t position() const;

    /// Set the current byte offset (for back-patching).
    void setPosition(size_t pos);
};
```

### 3.3 TlvDecoder

Reads TLV-encoded data from a buffer.

```cpp
class TlvDecoder {
public:
    /// Construct a decoder over the given buffer.
    TlvDecoder(const uint8_t* buf, size_t len);

    /// Read a VAR-NUMBER.
    Result<uint64_t> readVarNumber();

    /// Read a non-negative integer of the specified byte length (1, 2, 4, or 8).
    Result<uint64_t> readNonNegativeInteger(size_t numBytes);

    /// Read a TLV Type field.
    Result<uint32_t> readType();

    /// Read a TLV Length field.
    Result<size_t> readLength();

    /// TLV header (Type + Length).
    struct TlvHeader {
        uint32_t type;
        size_t length;
    };

    /// Read a TLV header (Type and Length) in one call.
    Result<TlvHeader> readTlvHeader();

    /// Read the specified number of bytes into an output buffer.
    Error readBytes(uint8_t* out, size_t len);

    /// Skip the specified number of bytes.
    Error skip(size_t len);

    /// Number of unread bytes.
    size_t remaining() const;

    /// Pointer to the current read position.
    const uint8_t* current() const;

    /// True if there are remaining bytes.
    bool hasMore() const;

    /// Get the current byte offset.
    size_t position() const;

    /// Set the current byte offset.
    void setPosition(size_t pos);
};
```

### 3.4 Helper Functions

```cpp
/// Return the number of bytes needed to encode the given value as a VAR-NUMBER.
constexpr size_t varNumberSize(uint64_t value);

/// Return the number of bytes needed to encode the given value as a non-negative integer.
constexpr size_t nonNegativeIntegerSize(uint64_t value);
```

---

## 4. Name Class

```cpp
// ndn/name.hpp

namespace ndn {

/// A single Name component (a pointer into the parent Name buffer).
struct NameComponent {
    const uint8_t* value;  ///< Pointer to the component value
    size_t size;           ///< Number of bytes

    /// Interpret the component as a string_view.
    std::string_view asString() const;
};

class Name {
public:
    Name() = default;

    // -- Construction --------------------------------------------------------

    /// Parse a URI string (e.g. "/sensor/temperature") into a Name.
    /// The optional "ndn:" prefix is accepted. Percent-encoding (%XX) is supported.
    static Result<Name> fromUri(std::string_view uri);

    /// Decode a Name from TLV wire format.
    /// If bytesRead is non-null, the number of consumed bytes is stored there.
    static Result<Name> fromWire(const uint8_t* buf, size_t len,
                                 size_t* bytesRead = nullptr);

    // -- Conversion ----------------------------------------------------------

    /// Write the Name as a URI string into the buffer.
    /// Returns the number of characters written (excluding null terminator).
    size_t toUri(char* buf, size_t bufSize) const;

    /// Encode the Name to TLV wire format.
    Error encode(uint8_t* buf, size_t bufSize, size_t& encodedLen) const;

    // -- Component access ----------------------------------------------------

    /// Number of components in the Name.
    size_t componentCount() const;

    /// Return the component at the given index (0-based).
    /// Behavior is undefined when index is out of range.
    NameComponent component(size_t index) const;

    /// Append a string component.
    Error appendComponent(std::string_view comp);

    /// Append a binary component.
    Error appendComponent(const uint8_t* value, size_t len);

    // -- Comparison ----------------------------------------------------------

    /// Lexicographic comparison per the NDN specification.
    /// Returns negative if this < other, 0 if equal, positive if this > other.
    int compare(const Name& other) const;

    /// Returns true if the two Names are identical.
    bool equals(const Name& other) const;

    /// Returns true if this Name is a prefix of the other Name.
    bool isPrefixOf(const Name& other) const;

    // -- Hashing -------------------------------------------------------------

    /// Compute a 32-bit hash (used for PIT / CS lookups).
    uint32_t hash() const;

    // -- State ---------------------------------------------------------------

    /// True if the Name has no components.
    bool empty() const;

    /// Pointer to the raw TLV-encoded Name Value bytes.
    const uint8_t* wireValue() const;

    /// Length of the TLV-encoded Name Value.
    size_t wireLength() const;
};

// Comparison operators
bool operator==(const Name& a, const Name& b);
bool operator!=(const Name& a, const Name& b);
bool operator<(const Name& a, const Name& b);

}  // namespace ndn
```

---

## 5. Interest Class

The Interest packet is sent by a consumer to request data. The only required
field is the Name; all other fields are optional.

```cpp
// ndn/interest.hpp

namespace ndn {

class Interest {
public:
    /// Construct an empty Interest (empty Name, default lifetime 4000 ms).
    Interest() = default;

    /// Construct an Interest with the given Name.
    explicit Interest(const Name& name);

    // -- Decoding / Encoding -------------------------------------------------

    /// Decode an Interest from TLV wire format.
    static Result<Interest> fromWire(const uint8_t* buf, size_t len);

    /// Encode the Interest to TLV wire format.
    Error encode(uint8_t* buf, size_t bufSize, size_t& encodedLen) const;

    // -- Name ----------------------------------------------------------------

    const Name& name() const;
    Name& name();
    Interest& setName(const Name& name);
    Error setName(std::string_view uri);

    // -- CanBePrefix ---------------------------------------------------------

    /// When true, the Interest accepts Data whose Name is a prefix match.
    /// Default: false.
    bool canBePrefix() const;
    Interest& setCanBePrefix(bool canBePrefix);

    // -- MustBeFresh ---------------------------------------------------------

    /// When true, only fresh Data (within its FreshnessPeriod) may satisfy
    /// this Interest from a Content Store. Default: false.
    bool mustBeFresh() const;
    Interest& setMustBeFresh(bool mustBeFresh);

    // -- Nonce ---------------------------------------------------------------

    /// 32-bit random value used for loop detection.
    std::optional<uint32_t> nonce() const;
    Interest& setNonce(uint32_t nonce);
    Interest& generateNonce();

    // -- InterestLifetime ----------------------------------------------------

    /// How long (ms) the Interest remains pending. Default: 4000 ms.
    uint32_t lifetime() const;
    Interest& setLifetime(uint32_t lifetimeMs);

    // -- HopLimit ------------------------------------------------------------

    /// Maximum number of hops the Interest may traverse (0-255).
    /// Decremented at each hop; the Interest is dropped when it reaches 0.
    std::optional<uint8_t> hopLimit() const;
    Interest& setHopLimit(uint8_t limit);
    Interest& decrementHopLimit();

    // -- ForwardingHint ------------------------------------------------------

    /// Add a ForwardingHint (a Name indicating a route toward the producer).
    Error addForwardingHint(const Name& name);
    Error addForwardingHint(std::string_view uri);

    /// Number of ForwardingHint entries.
    size_t forwardingHintCount() const;

    /// Return the ForwardingHint at the given index, or nullptr if out of range.
    const Name* forwardingHint(size_t index) const;

    /// Remove all ForwardingHints.
    void clearForwardingHints();

    /// True if at least one ForwardingHint is set.
    bool hasForwardingHint() const;

    // -- ApplicationParameters -----------------------------------------------

    /// Pointer to ApplicationParameters data, or nullptr if not set.
    const uint8_t* applicationParameters() const;

    /// Size of the ApplicationParameters in bytes.
    size_t applicationParametersSize() const;

    /// Set ApplicationParameters (data is copied into an internal buffer).
    Interest& setApplicationParameters(const uint8_t* params, size_t len);

    // -- Signature (Signed Interest) -----------------------------------------

    /// True if the Interest carries a signature.
    bool isSigned() const;

    /// The signature algorithm used.
    SignatureType signatureType() const;

    /// 8-byte random nonce for replay attack protection.
    /// Returns nullptr if not set.
    const uint8_t* signatureNonce() const;

    /// Signature timestamp (ms since Unix epoch). nullopt if not set.
    std::optional<uint64_t> signatureTime() const;

    /// Signature sequence number (for replay protection). nullopt if not set.
    std::optional<uint64_t> signatureSeqNum() const;
    Interest& setSignatureSeqNum(uint64_t seqNum);

    // -- KeyLocator ----------------------------------------------------------

    /// Return the KeyLocator Name, or nullptr if not set.
    const Name* keyLocator() const;
    bool hasKeyLocator() const;
    Interest& setKeyLocator(const Name& name);
    Interest& clearKeyLocator();

    // -- Signature value access ----------------------------------------------

    const uint8_t* signatureValue() const;
    size_t signatureValueSize() const;

    // -- Signing methods -----------------------------------------------------

    /// Sign with SHA-256 digest (integrity only, no key required).
    Error signWithDigestSha256();

    /// Sign with HMAC-SHA256.
    /// @param key  Symmetric key bytes.
    /// @param keyLen  Key length in bytes.
    Error signWithHmac(const uint8_t* key, size_t keyLen);

    /// Sign with ECDSA P-256.
    /// @param privKey  Private key (32 bytes).
    Error signWithEcdsa(const uint8_t* privKey);

    // -- Verification methods ------------------------------------------------

    /// Verify a DigestSha256 signature.
    bool verifyDigestSha256() const;

    /// Verify an HMAC-SHA256 signature.
    bool verifyHmac(const uint8_t* key, size_t keyLen) const;

    /// Verify an ECDSA P-256 signature.
    /// @param pubKey  Public key (65 bytes, uncompressed 0x04 || X || Y).
    bool verifyEcdsa(const uint8_t* pubKey) const;
};

}  // namespace ndn
```

---

## 6. Data Class

The Data packet is returned by a producer in response to an Interest.
The only required field is the Name; Content and other fields are optional.

```cpp
// ndn/data.hpp

namespace ndn {

class Data {
public:
    /// Construct an empty Data packet.
    Data() = default;

    /// Construct a Data with the given Name.
    explicit Data(const Name& name);

    // -- Decoding / Encoding -------------------------------------------------

    /// Decode a Data packet from TLV wire format.
    static Result<Data> fromWire(const uint8_t* buf, size_t len);

    /// Encode the Data packet to TLV wire format.
    Error encode(uint8_t* buf, size_t bufSize, size_t& encodedLen) const;

    // -- Name ----------------------------------------------------------------

    const Name& name() const;
    Name& name();
    Data& setName(const Name& name);
    Error setName(std::string_view uri);

    // -- Content -------------------------------------------------------------

    /// Pointer to the content bytes.
    const uint8_t* content() const;

    /// Number of content bytes.
    size_t contentSize() const;

    /// True if content has been set (size > 0).
    bool hasContent() const;

    /// Set binary content. Returns Error::BufferTooSmall if size > DATA_MAX_CONTENT_SIZE.
    Error setContent(const uint8_t* data, size_t size);

    /// Set string content.
    Error setContent(std::string_view str);

    // -- ContentType ---------------------------------------------------------

    /// Get the content type. Default: ContentType::Blob.
    ContentType contentType() const;

    /// Set the content type.
    Data& setContentType(ContentType type);

    /// True if ContentType is Link.
    bool isLink() const;

    // -- FreshnessPeriod -----------------------------------------------------

    /// How long (ms) the Data remains fresh after arrival at a Content Store.
    std::optional<uint32_t> freshnessPeriod() const;
    Data& setFreshnessPeriod(uint32_t periodMs);

    // -- FinalBlockId --------------------------------------------------------

    /// Segment number of the final block in a segmented transfer.
    std::optional<uint64_t> finalBlockId() const;
    bool hasFinalBlockId() const;
    Data& setFinalBlockId(uint64_t segmentNum);
    Data& clearFinalBlockId();

    // -- Signature -----------------------------------------------------------

    /// Get the signature algorithm.
    SignatureType signatureType() const;
    Data& setSignatureType(SignatureType type);

    /// KeyLocator Name identifying the signing key.
    /// Required for RSA / ECDSA / Ed25519; forbidden for DigestSha256.
    const Name* keyLocator() const;
    bool hasKeyLocator() const;
    Data& setKeyLocator(const Name& name);
    Data& clearKeyLocator();

    /// Raw signature bytes.
    const uint8_t* signatureValue() const;
    size_t signatureValueSize() const;
    bool hasSignature() const;

    // -- Signing methods -----------------------------------------------------

    /// Sign with SHA-256 digest (integrity only).
    Error signWithDigestSha256();

    /// Sign with HMAC-SHA256.
    Error signWithHmac(const uint8_t* key, size_t keyLen);

    /// Sign with ECDSA P-256.
    /// @param privKey  Private key (32 bytes).
    Error signWithEcdsa(const uint8_t* privKey);

    // -- Verification methods ------------------------------------------------

    /// Verify a DigestSha256 signature.
    bool verifyDigestSha256() const;

    /// Verify an HMAC-SHA256 signature.
    bool verifyHmac(const uint8_t* key, size_t keyLen) const;

    /// Verify an ECDSA P-256 signature.
    /// @param pubKey  Public key (65 bytes, uncompressed).
    bool verifyEcdsa(const uint8_t* pubKey) const;
};

}  // namespace ndn
```

---

## 7. Crypto Utilities

### 7.1 crypto.hpp

Low-level cryptographic primitives backed by mbedtls (bundled with ESP-IDF).

```cpp
namespace ndn::crypto {

/// Compute a SHA-256 hash.
/// @param data  Input data.
/// @param len   Input length in bytes.
/// @param out   Output buffer (must be at least 32 bytes).
Error sha256(const uint8_t* data, size_t len, uint8_t* out);

/// Compute HMAC-SHA256.
/// @param key     Key bytes.
/// @param keyLen  Key length.
/// @param data    Input data.
/// @param dataLen Input length.
/// @param out     Output buffer (must be at least 32 bytes).
Error hmacSha256(const uint8_t* key, size_t keyLen,
                 const uint8_t* data, size_t dataLen,
                 uint8_t* out);

/// Constant-time buffer comparison (to avoid timing attacks).
bool constantTimeCompare(const uint8_t* lhs, const uint8_t* rhs, size_t len);

/// Generate an ECDSA P-256 key pair.
/// @param privKey  Output private key (32 bytes).
/// @param pubKey   Output public key (65 bytes, uncompressed: 0x04 || X || Y).
Error ecdsaP256GenerateKeyPair(uint8_t* privKey, uint8_t* pubKey);

/// Sign data with ECDSA P-256.
/// The function hashes the data with SHA-256 internally before signing.
/// @param privKey  Private key (32 bytes).
/// @param data     Data to sign.
/// @param dataLen  Data length.
/// @param sig      Output signature buffer (up to 72 bytes, DER-encoded).
/// @param sigLen   Actual signature length written.
Error ecdsaP256Sign(const uint8_t* privKey,
                    const uint8_t* data, size_t dataLen,
                    uint8_t* sig, size_t* sigLen);

/// Verify an ECDSA P-256 signature.
/// @param pubKey   Public key (65 bytes, uncompressed).
/// @param data     Signed data.
/// @param dataLen  Data length.
/// @param sig      Signature (DER-encoded).
/// @param sigLen   Signature length.
/// @return true if the signature is valid.
bool ecdsaP256Verify(const uint8_t* pubKey,
                     const uint8_t* data, size_t dataLen,
                     const uint8_t* sig, size_t sigLen);

}  // namespace ndn::crypto
```

---

## 8. Certificate

### 8.1 ValidityPeriod

Represents the time interval during which a certificate is valid.
Timestamps use ISO 8601-1:2019 compact format (`YYYYMMDDThhmmss`).

```cpp
// ndn/certificate.hpp

namespace ndn {

constexpr size_t VALIDITY_TIMESTAMP_SIZE  = 15;   ///< Length of "YYYYMMDDThhmmss"
constexpr size_t CERTIFICATE_MAX_KEY_SIZE = 256;  ///< Max public key size (DER)

class ValidityPeriod {
public:
    ValidityPeriod() = default;

    /// Create from two ISO 8601 compact timestamp strings.
    static Result<ValidityPeriod> fromStrings(std::string_view notBefore,
                                              std::string_view notAfter);

    /// Decode from TLV wire format.
    static Result<ValidityPeriod> fromWire(const uint8_t* buf, size_t len,
                                           size_t* bytesRead = nullptr);

    /// Encode to TLV wire format.
    Error encode(uint8_t* buf, size_t bufSize, size_t& encodedLen) const;

    // -- NotBefore -----------------------------------------------------------

    /// Set the NotBefore time using individual date/time components.
    Error setNotBefore(uint16_t year, uint8_t month, uint8_t day,
                       uint8_t hour, uint8_t minute, uint8_t second);

    /// Set the NotBefore time from an ISO 8601 compact string.
    Error setNotBefore(std::string_view timestamp);

    /// Return the NotBefore string (15 chars, not null-terminated).
    const char* notBefore() const;

    // -- NotAfter ------------------------------------------------------------

    /// Set the NotAfter time using individual date/time components.
    Error setNotAfter(uint16_t year, uint8_t month, uint8_t day,
                      uint8_t hour, uint8_t minute, uint8_t second);

    /// Set the NotAfter time from an ISO 8601 compact string.
    Error setNotAfter(std::string_view timestamp);

    /// Return the NotAfter string (15 chars, not null-terminated).
    const char* notAfter() const;

    // -- Validation ----------------------------------------------------------

    /// Check whether the given timestamp falls within the validity period.
    bool isValidAt(std::string_view currentTimestamp) const;

    /// Check equality with another ValidityPeriod.
    bool equals(const ValidityPeriod& other) const;
};
```

### 8.2 Certificate

An NDN certificate is a Data packet with `ContentType=Key` whose Content
carries a public key. The certificate name follows the pattern:
`/<IdentityName>/KEY/<KeyId>/<IssuerId>/<Version>`

```cpp
class Certificate {
public:
    Certificate() = default;

    /// Create a Certificate from a Data packet.
    /// Returns an error if ContentType is not Key.
    static Result<Certificate> fromData(const Data& data);

    /// Decode a Certificate from TLV wire format.
    static Result<Certificate> fromWire(const uint8_t* buf, size_t len);

    /// Convert this Certificate to a Data packet.
    Error toData(Data& data) const;

    /// Encode the Certificate to TLV wire format.
    Error encode(uint8_t* buf, size_t bufSize, size_t& encodedLen) const;

    // -- Identity Name -------------------------------------------------------

    const Name& identityName() const;
    Certificate& setIdentityName(const Name& name);
    Error setIdentityName(std::string_view uri);

    // -- Key ID --------------------------------------------------------------

    const uint8_t* keyId() const;
    size_t keyIdSize() const;
    Error setKeyId(const uint8_t* id, size_t len);

    // -- Issuer ID -----------------------------------------------------------

    const uint8_t* issuerId() const;
    size_t issuerIdSize() const;
    Error setIssuerId(const uint8_t* id, size_t len);
    Error setIssuerId(std::string_view id);

    // -- Version -------------------------------------------------------------

    uint64_t version() const;
    Certificate& setVersion(uint64_t version);

    // -- Public Key ----------------------------------------------------------

    const uint8_t* publicKey() const;
    size_t publicKeySize() const;
    Error setPublicKey(const uint8_t* key, size_t len);

    // -- Validity Period -----------------------------------------------------

    const ValidityPeriod& validity() const;
    ValidityPeriod& validity();
    Certificate& setValidity(const ValidityPeriod& validity);

    // -- Signature -----------------------------------------------------------

    SignatureType signatureType() const;
    Certificate& setSignatureType(SignatureType type);

    Error signWithDigestSha256();
    Error signWithHmac(const uint8_t* key, size_t keyLen);
    bool verifyDigestSha256() const;
    bool verifyHmac(const uint8_t* key, size_t keyLen) const;

    // -- Utilities -----------------------------------------------------------

    /// Build the full certificate Name:
    /// /<IdentityName>/KEY/<KeyId>/<IssuerId>/<Version>
    Error buildName(Name& name) const;

    /// Check if the certificate is valid at the given ISO 8601 timestamp.
    bool isValidAt(std::string_view timestamp) const;
};

}  // namespace ndn
```

---

## 9. Link Object

A Link Object is a Data packet with `ContentType=Link` whose Content encodes
a list of Names (delegations) used as forwarding hints.

```cpp
// ndn/link.hpp

namespace ndn {

class Link {
public:
    Link() = default;

    /// Construct a Link with the given Name.
    explicit Link(const Name& name);

    // -- Delegation management -----------------------------------------------

    /// Add a delegation (Name). Delegations should be added in priority order
    /// (first added = highest priority).
    /// Returns Error::Full if LINK_MAX_DELEGATIONS reached,
    ///         Error::InvalidParam if the name is already present.
    Error addDelegation(const Name& delegation);
    Error addDelegation(std::string_view uri);

    /// Number of delegations.
    size_t delegationCount() const;

    /// Return the delegation at the given index, or nullptr if out of range.
    const Name* delegation(size_t index) const;

    /// Remove all delegations.
    void clearDelegations();

    /// Check if a Name is already listed as a delegation.
    bool hasDelegation(const Name& name) const;

    // -- Name access ---------------------------------------------------------

    const Name& name() const;
    Name& name();
    Link& setName(const Name& name);
    Error setName(std::string_view uri);

    // -- Conversion to/from Data ---------------------------------------------

    /// Populate a Data packet from this Link (ContentType=Link).
    /// Does not sign the Data; call a sign method on the Data after this.
    Error toData(Data& data) const;

    /// Decode a Link from a Data packet.
    /// Returns Error::InvalidPacket if ContentType is not Link.
    static Result<Link> fromData(const Data& data);
};

}  // namespace ndn
```

---

## 10. PIT (Pending Interest Table)

```cpp
// ndn/pit.hpp

namespace ndn {

constexpr size_t PIT_MAX_ENTRIES        = 50;
constexpr size_t PIT_MAX_FACES_PER_ENTRY = 5;

/// Result of inserting an Interest into the PIT.
enum class PitInsertResult : uint8_t {
    New,         ///< A new entry was created
    Aggregated,  ///< An existing entry was updated (Face added)
    Duplicate,   ///< Same nonce detected (loop)
    Full,        ///< Table is full
};

/// A single PIT entry tracking one pending Interest.
class PitEntry {
public:
    const Name& name() const;
    uint32_t nonce() const;
    TimeMs expireTime() const;

    size_t faceCount() const;
    FaceId face(size_t index) const;

    bool hasFace(FaceId faceId) const;
    bool addFace(FaceId faceId);
};

/// The Pending Interest Table.
///
/// Records incoming Interests so that returning Data can be forwarded
/// back to the correct downstream Face(s).
class Pit {
public:
    // -- Interest management -------------------------------------------------

    /// Insert an Interest.
    /// When an entry with the same Name already exists, the incoming Face is
    /// aggregated. If the same nonce is found, it is treated as a loop.
    PitInsertResult insert(const Interest& interest, FaceId incomingFace,
                           PitEntry** outEntry = nullptr);

    /// Find an entry by Name.
    PitEntry* find(const Name& name);
    const PitEntry* find(const Name& name) const;

    /// Remove an entry by pointer.
    void remove(PitEntry* entry);

    /// Remove an entry by Name.
    void remove(const Name& name);

    // -- Timeout processing --------------------------------------------------

    using TimeoutCallback = std::function<void(const PitEntry&)>;

    /// Remove expired entries and optionally invoke a callback for each.
    void processTimeouts(TimeMs now, TimeoutCallback callback = nullptr);

    // -- Statistics ----------------------------------------------------------

    size_t size() const;
    size_t capacity() const;  // PIT_MAX_ENTRIES

    struct Stats {
        uint32_t insertions  = 0;  ///< New entries created
        uint32_t aggregations = 0; ///< Face aggregations
        uint32_t duplicates  = 0;  ///< Loop detections
        uint32_t timeouts    = 0;  ///< Entries timed out
    };
    const Stats& stats() const;
};

}  // namespace ndn
```

---

## 11. CS (Content Store)

```cpp
// ndn/cs.hpp

namespace ndn {

constexpr size_t CS_DEFAULT_ENTRIES     = 15;
constexpr size_t CS_MANET_ENTRIES       = 100;
constexpr size_t CS_LARGE_MANET_ENTRIES = 200;

/// A single Content Store entry holding a cached Data packet.
class CsEntry {
public:
    const Data& data() const;

    /// Timestamp after which the Data is stale (0 = never expires).
    TimeMs staleTime() const;

    /// True if the Data is still fresh at the given time.
    bool isFresh(TimeMs now) const;
};

/// Content Store -- caches received Data packets.
///
/// Uses an LRU (Least Recently Used) replacement policy.
/// Entries are allocated on PSRAM (via init()).
class ContentStore {
public:
    ContentStore() = default;
    ~ContentStore();

    // Non-copyable, non-movable (manages PSRAM pointer).
    ContentStore(const ContentStore&) = delete;
    ContentStore& operator=(const ContentStore&) = delete;
    ContentStore(ContentStore&&) = delete;
    ContentStore& operator=(ContentStore&&) = delete;

    /// Initialize the entry array on PSRAM.
    /// Must be called exactly once before use.
    Error init(size_t maxEntries = CS_DEFAULT_ENTRIES);

    // -- Data management -----------------------------------------------------

    /// Insert (or replace) a Data packet in the cache.
    /// If the cache is full the least recently used entry is evicted.
    Error insert(const Data& data, TimeMs now);

    /// Look up a cached Data by Name.
    /// When mustBeFresh is true only entries within their FreshnessPeriod are returned.
    const CsEntry* find(const Name& name, bool mustBeFresh = false,
                        TimeMs now = 0) const;

    /// Remove a cached entry by Name.
    void remove(const Name& name);

    /// Remove all stale entries.
    void evictStale(TimeMs now);

    // -- Statistics ----------------------------------------------------------

    size_t size() const;
    size_t capacity() const;

    struct Stats {
        uint32_t hits       = 0;  ///< Cache hits
        uint32_t misses     = 0;  ///< Cache misses
        uint32_t insertions = 0;  ///< Insertions
        uint32_t evictions  = 0;  ///< Evictions
    };
    const Stats& stats() const;
};

}  // namespace ndn
```

---

## 12. FIB (Forwarding Information Base)

```cpp
// ndn/fib.hpp

namespace ndn {

constexpr size_t FIB_MAX_ENTRIES  = 30;
constexpr size_t FIB_MAX_NEXTHOPS = 3;

/// A next-hop entry (Face + cost).
struct FibNexthop {
    FaceId faceId = FACE_ID_INVALID;
    uint8_t cost  = 0;  ///< Lower cost = higher priority
};

/// A single FIB entry (prefix + list of next-hops).
class FibEntry {
public:
    const Name& prefix() const;

    size_t nexthopCount() const;
    const FibNexthop& nexthop(size_t index) const;

    /// Add (or update) a next-hop. Returns false if the list is full.
    bool addNexthop(FaceId faceId, uint8_t cost = 0);

    /// Remove a next-hop. Returns false if not found.
    bool removeNexthop(FaceId faceId);
};

/// The Forwarding Information Base.
///
/// Maps Name prefixes to outgoing Face(s). Supports longest-prefix-match lookup.
class Fib {
public:
    // -- Route management ----------------------------------------------------

    Error addRoute(const Name& prefix, FaceId faceId, uint8_t cost = 0);
    void removeRoute(const Name& prefix, FaceId faceId);
    void removeRoute(const Name& prefix);

    /// Remove the given Face from all entries (used when a Face goes down).
    void removeFace(FaceId faceId);

    // -- Lookup --------------------------------------------------------------

    /// Longest-prefix-match lookup.
    const FibEntry* findLongestMatch(const Name& name) const;

    /// Exact-match lookup.
    const FibEntry* findExact(const Name& prefix) const;
    FibEntry* findExact(const Name& prefix);

    // -- Statistics ----------------------------------------------------------

    size_t size() const;
    size_t capacity() const;  // FIB_MAX_ENTRIES
};

}  // namespace ndn
```

---

## 13. Face (Abstract Base Class)

```cpp
// ndn/face.hpp

namespace ndn {

/// Callback invoked when a packet is received on a Face.
using PacketCallback = std::function<void(FaceId faceId,
                                          const uint8_t* data,
                                          size_t len)>;

/// Abstract base class for network transports.
class Face {
public:
    virtual ~Face() = default;

    virtual FaceId id() const = 0;

    virtual Error start() = 0;
    virtual void stop()   = 0;

    /// Send a packet (default destination).
    virtual Error send(const uint8_t* data, size_t len) = 0;

    /// Send a packet to a specific peer.
    virtual Error sendTo(FaceId destFace, const uint8_t* data, size_t len) = 0;

    /// Broadcast a packet to all peers.
    virtual Error broadcast(const uint8_t* data, size_t len) = 0;

    /// Maximum payload size that can be sent in one frame.
    virtual size_t maxPayloadSize() const = 0;

    /// Set the packet-received callback.
    void setPacketCallback(PacketCallback callback);

protected:
    /// Derived classes call this when a packet arrives.
    void onPacketReceived(FaceId faceId, const uint8_t* data, size_t len);

    PacketCallback packetCallback_;
};

}  // namespace ndn
```

---

## 14. ESP-NOW Face

```cpp
// adapters/espnow_face.hpp

namespace ndn {

constexpr size_t ESPNOW_MAX_PAYLOAD = 1470;  ///< ESP-NOW v2.0 max payload
constexpr size_t ESPNOW_MAX_PEERS   = 20;

constexpr uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/// Derive a FaceId from a MAC address (lower 2 bytes + 2).
inline FaceId macToFaceId(const uint8_t* mac);

/// Peer information.
struct PeerInfo {
    uint8_t mac[6];     ///< MAC address
    FaceId faceId;      ///< Face ID
    bool inUse;         ///< In-use flag
    uint32_t lastSeen;  ///< Last reception time (ms)
};

/// Face implementation using the ESP-NOW protocol.
///
/// Supports broadcast and unicast. Peers are automatically discovered
/// when packets are received. A receive queue decouples the ISR callback
/// from the main processing loop.
class EspNowFace : public Face {
public:
    explicit EspNowFace(FaceId faceId = 2);
    ~EspNowFace() override;

    // Face interface
    FaceId id() const override;
    Error start() override;      ///< Wi-Fi must already be initialized
    void stop() override;
    Error send(const uint8_t* data, size_t len) override;      ///< Broadcasts by default
    Error sendTo(FaceId destFace, const uint8_t* data, size_t len) override;
    Error broadcast(const uint8_t* data, size_t len) override;
    size_t maxPayloadSize() const override;  ///< Returns ESPNOW_MAX_PAYLOAD

    // -- Peer management -----------------------------------------------------

    /// Add a peer by MAC address. Returns the new FaceId, or FACE_ID_INVALID on failure.
    FaceId addPeer(const uint8_t* mac);

    /// Remove a peer by FaceId.
    void removePeer(FaceId faceId);

    /// Look up the MAC address for a FaceId. Returns false if not found.
    bool getMacAddress(FaceId faceId, uint8_t* mac) const;

    /// Number of registered peers.
    size_t peerCount() const;

    // -- Event processing ----------------------------------------------------

    /// Drain the receive queue and deliver packets via the callback.
    /// Must be called periodically from the main loop.
    void processReceiveQueue();

    // -- MAC address filtering -----------------------------------------------

    /// Accept packets only from one specific MAC address (nullptr to disable).
    void setMacFilter(const uint8_t* mac);

    /// Accept packets only from the given set of MAC addresses (up to MAX_MAC_FILTERS).
    /// Useful for creating virtual topologies in multi-hop experiments.
    static constexpr size_t MAX_MAC_FILTERS = 4;
    void setMacFilters(const uint8_t macs[][6], size_t count);

    /// Disable all MAC address filters.
    void clearMacFilters();

    /// True if MAC filtering is active.
    bool hasMacFilter() const;

    /// Access the singleton instance (for static ESP-NOW callbacks).
    static EspNowFace* instance();
};

}  // namespace ndn
```

---

## 15. Forwarder

```cpp
// ndn/forwarder.hpp

namespace ndn {

/// Callback for incoming Interests that match a registered prefix.
using InterestCallback = std::function<void(const Interest&, FaceId)>;

/// Callback when Data arrives in response to expressInterest().
using DataCallback = std::function<void(const Data&)>;

/// Callback when an expressed Interest times out.
using TimeoutCallback = std::function<void(const Interest&)>;

constexpr size_t FORWARDER_MAX_FACES    = 8;
constexpr size_t FORWARDER_MAX_PREFIXES = 16;

/// Central component of the NDN stack: integrates PIT, CS, and FIB
/// to forward Interest and Data packets, and exposes application-level APIs.
class Forwarder {
public:
    Forwarder();

    /// Initialize the Forwarder (including the Content Store).
    Error init(size_t csMaxEntries = CS_DEFAULT_ENTRIES);

    // -- Face management -----------------------------------------------------

    /// Register a Face with the Forwarder.
    Error addFace(Face* face);

    /// Unregister a Face (also removes related FIB next-hops).
    void removeFace(FaceId faceId);

    // -- Consumer API --------------------------------------------------------

    /// Send an Interest and wait for Data.
    /// onData is called when matching Data arrives; onTimeout is called when
    /// the Interest expires without a response.
    Error expressInterest(const Interest& interest,
                          DataCallback onData,
                          TimeoutCallback onTimeout = nullptr);

    /// Send an Interest without creating a PIT entry
    /// (e.g. for Sync Interests where no Data reply is expected).
    Error sendInterest(const Interest& interest);

    // -- Producer API --------------------------------------------------------

    /// Register a prefix. The callback is invoked for each incoming Interest
    /// whose Name matches the prefix.
    Error registerPrefix(const Name& prefix, InterestCallback callback);
    Error registerPrefix(std::string_view prefixUri, InterestCallback callback);

    /// Unregister a previously registered prefix.
    void unregisterPrefix(const Name& prefix);

    /// Respond with a Data packet. The Forwarder looks up the PIT and forwards
    /// Data to the recorded downstream Face(s). The Data is also cached in the CS.
    Error putData(const Data& data);

    // -- FIB route management ------------------------------------------------

    Error addRoute(const Name& prefix, FaceId faceId, uint8_t cost = 0);
    Error addRoute(std::string_view prefixUri, FaceId faceId, uint8_t cost = 0);

    // -- Event loop ----------------------------------------------------------

    /// Process pending timeouts and other events.
    /// Must be called periodically from the main loop.
    void processEvents();

    // -- Statistics ----------------------------------------------------------

    struct Stats {
        uint32_t interestsReceived = 0;
        uint32_t interestsSent     = 0;
        uint32_t dataReceived      = 0;
        uint32_t dataSent          = 0;
        uint32_t cacheHits         = 0;
        uint32_t cacheMisses       = 0;
    };
    const Stats& stats() const;

    // -- Internal component access (for testing) -----------------------------

    Pit& pit();
    ContentStore& cs();
    Fib& fib();
};

}  // namespace ndn
```

---

## 16. Convenience API

The `ndn.hpp` header includes all public headers and provides free functions
that operate on a global singleton `Forwarder`.

```cpp
// ndn/ndn.hpp

#include <ndn/certificate.hpp>
#include <ndn/common.hpp>
#include <ndn/crypto.hpp>
#include <ndn/cs.hpp>
#include <ndn/data.hpp>
#include <ndn/face.hpp>
#include <ndn/fib.hpp>
#include <ndn/forwarder.hpp>
#include <ndn/interest.hpp>
#include <ndn/link.hpp>
#include <ndn/name.hpp>
#include <ndn/pit.hpp>
#include <ndn/signature.hpp>
#include <ndn/tlv.hpp>

namespace ndn {

/// Initialize the global Forwarder. Call this before any other NDN API.
Error initialize();

/// Get the global Forwarder instance.
Forwarder& getForwarder();

/// Send an Interest via the global Forwarder.
inline Error expressInterest(const Interest& interest,
                             DataCallback onData,
                             TimeoutCallback onTimeout = nullptr);

/// Register a prefix on the global Forwarder.
inline Error registerPrefix(std::string_view prefix, InterestCallback callback);

/// Respond with Data via the global Forwarder.
inline Error putData(const Data& data);

/// Process events on the global Forwarder.
inline void processEvents();

}  // namespace ndn
```

---

## 17. Usage Examples

### Consumer

```cpp
#include <ndn/ndn.hpp>

extern "C" void app_main() {
    ndn::initialize();

    auto& fwd = ndn::getForwarder();

    // Create and start the ESP-NOW Face
    static ndn::EspNowFace espNowFace;
    espNowFace.start();
    fwd.addFace(&espNowFace);

    // Build an Interest
    ndn::Interest interest;
    interest.setName("/sensor/temperature")
            .setLifetime(4000)
            .generateNonce();

    // Send the Interest and wait for Data
    fwd.expressInterest(interest,
        [](const ndn::Data& data) {
            ESP_LOGI("APP", "Data received: %.*s",
                     (int)data.contentSize(),
                     (const char*)data.content());
        },
        [](const ndn::Interest& interest) {
            ESP_LOGW("APP", "Interest timed out");
        }
    );

    // Main event loop
    while (true) {
        espNowFace.processReceiveQueue();
        fwd.processEvents();
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
```

### Producer

```cpp
#include <ndn/ndn.hpp>

extern "C" void app_main() {
    ndn::initialize();

    auto& fwd = ndn::getForwarder();

    static ndn::EspNowFace espNowFace;
    espNowFace.start();
    fwd.addFace(&espNowFace);

    // Register a prefix and reply to matching Interests
    fwd.registerPrefix("/sensor/temperature",
        [](const ndn::Interest& interest, ndn::FaceId incomingFace) {
            // Read the sensor value
            float temp = readTemperature();
            char buf[32];
            snprintf(buf, sizeof(buf), "%.1f", temp);

            ndn::Data data;
            data.setName(interest.name());
            data.setContent(buf);
            data.setFreshnessPeriod(5000);  // fresh for 5 seconds

            ndn::putData(data);
        }
    );

    while (true) {
        espNowFace.processReceiveQueue();
        fwd.processEvents();
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
```

### Signed Interest (ECDSA)

```cpp
#include <ndn/ndn.hpp>

// Generate a key pair once
uint8_t privKey[32], pubKey[65];
ndn::crypto::ecdsaP256GenerateKeyPair(privKey, pubKey);

// Build and sign an Interest
ndn::Interest interest;
interest.setName("/secure/command");
interest.setApplicationParameters(payload, payloadLen);
interest.setKeyLocator(keyName);
interest.signWithEcdsa(privKey);

// On the receiver side, verify the signature
auto result = ndn::Interest::fromWire(buf, len);
if (result.ok() && result.value.verifyEcdsa(pubKey)) {
    // Signature is valid
}
```

### Certificate

```cpp
#include <ndn/ndn.hpp>

// Create a certificate
ndn::Certificate cert;
cert.setIdentityName("/example/user");
cert.setKeyId(keyIdBytes, 8);
cert.setIssuerId("self");
cert.setVersion(1);
cert.setPublicKey(pubKey, 65);
cert.validity().setNotBefore(2024, 1, 1, 0, 0, 0);
cert.validity().setNotAfter(2025, 12, 31, 23, 59, 59);

// Self-sign
cert.signWithDigestSha256();

// Encode to wire format
uint8_t buf[512];
size_t len;
cert.encode(buf, sizeof(buf), len);
```

### Link Object and ForwardingHint

```cpp
#include <ndn/ndn.hpp>

// Create a Link Object
ndn::Link link;
link.setName("/example/link");
link.addDelegation("/ndn/jp/provider1");
link.addDelegation("/ndn/us/provider2");

// Convert to a signed Data packet
ndn::Data linkData;
link.toData(linkData);
linkData.signWithDigestSha256();

// Use delegations as ForwardingHints in an Interest
ndn::Interest interest;
interest.setName("/content/video");
auto decoded = ndn::Link::fromData(linkData);
if (decoded.ok()) {
    for (size_t i = 0; i < decoded.value.delegationCount(); ++i) {
        interest.addForwardingHint(*decoded.value.delegation(i));
    }
}
```
