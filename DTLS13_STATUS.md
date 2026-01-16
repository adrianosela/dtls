# DTLS 1.3 Implementation Status

## HelloRetryRequest Implementation

### Completed ✓

1. **Wire Format** (`pkg/protocol/handshake/message_hello_retry_request_13.go`)
   - `MessageHelloRetryRequest13` struct
   - Marshal/Unmarshal implementation
   - HelloRetryRequest magic random value (SHA-256 of "HelloRetryRequest")
   - Helper functions: `IsHelloRetryRequest()`, `IsHelloRetryRequestFromRandom()`
   - Comprehensive test coverage

2. **Integration with Handshake System** (`pkg/protocol/handshake/handshake.go`)
   - Automatic detection of HelloRetryRequest vs ServerHello based on magic random value
   - `isHelloRetryRequestBytes()` helper function
   - Proper unmarshaling of HRR messages

3. **Extension Support**
   - Works with existing `KeyShare` extension (`SelectedGroup` field)
   - Works with `CookieExt` extension
   - Works with `SupportedVersions` extension

4. **Test Coverage**
   - Unit tests for message marshal/unmarshal
   - Round-trip tests
   - Integration tests with Handshake wrapper
   - Tests with key_share extension (most common use case)
   - Tests with cookie extension (DoS protection)
   - Fuzz tests

### Stub Files for Future Implementation 🚧

1. **DTLS 1.3 Handshake Flow** (`handshake_dtls13.go`)
   - `handleClientHelloDTLS13()` - Process ClientHello, return ServerHello or HRR
   - `shouldSendHelloRetryRequest()` - Determine if HRR is needed
   - `buildHelloRetryRequest()` - Construct HRR with appropriate extensions
   - `handleHelloRetryRequest()` - Client-side HRR processing
   - `validateHelloRetryRequest()` - RFC 8446 compliance validation
   - `retryClientHelloWithHRR()` - Generate updated ClientHello after HRR

2. **Test Stubs** (`handshake_dtls13_test.go`)
   - `TestDTLS13HelloRetryRequestFlow` - Full HRR flow integration test
   - `TestHelloRetryRequestKeyShareSelection` - Key share group negotiation
   - `TestHelloRetryRequestCookie` - Cookie extension for DoS protection
   - `TestHelloRetryRequestValidation` - RFC compliance validation

All stub tests are marked with `t.Skip()` and include TODO comments.

## What's Ready to Use

- ✅ Wire format encoding/decoding
- ✅ Message structure and validation
- ✅ Integration with existing extensions
- ✅ Automatic HRR detection in handshake system

## What's Blocked

The following require DTLS 1.3 handshake and key derivation to be complete:

- ❌ **DTLS 1.3 Handshake State Machine** - Different from DTLS 1.2 flights
- ❌ **Key Derivation** - DTLS 1.3 uses HKDF (blocked by #738)
- ❌ **Record Protection** - DTLS 1.3 record layer changes
- ❌ **Connection Management** - Integration with Conn

## Usage Example (Once DTLS 1.3 is Complete)

```go
import (
    "github.com/pion/dtls/v3/pkg/crypto/elliptic"
    "github.com/pion/dtls/v3/pkg/protocol"
    "github.com/pion/dtls/v3/pkg/protocol/extension"
    "github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// Server-side: Build HelloRetryRequest
selectedGroup := elliptic.X25519
hrr := &handshake.MessageHelloRetryRequest13{
    Version:       protocol.Version{Major: 0xFE, Minor: 0xFD}, // DTLS 1.2 for compatibility
    SessionID:     clientSessionID, // Echo from ClientHello
    CipherSuiteID: 0x1301,          // TLS_AES_128_GCM_SHA256
    Extensions: []extension.Extension{
        &extension.SupportedVersions{
            Versions: []protocol.Version{{Major: 0xFE, Minor: 0xFC}}, // DTLS 1.3
        },
        &extension.KeyShare{
            SelectedGroup: &selectedGroup, // Request client to use X25519
        },
    },
}

// Marshal for sending
data, err := hrr.Marshal()
```

## References

- RFC 8446 Section 4.1.4: HelloRetryRequest
- RFC 9147: DTLS 1.3
- Issue #738: Key derivation blocker
