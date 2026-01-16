// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"crypto/sha256"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"golang.org/x/crypto/cryptobyte"
)

// HelloRetryRequestRandomBytes is the special Random value that identifies a HelloRetryRequest.
// Per RFC 8446 Section 4.1.3: "with Random set to the special value of the SHA-256 of
// 'HelloRetryRequest'":
//
//	CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
//	C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
var HelloRetryRequestRandomBytes = func() [RandomLength]byte {
	hash := sha256.Sum256([]byte("HelloRetryRequest"))
	var result [RandomLength]byte
	copy(result[:], hash[:])
	return result
}()

// MessageHelloRetryRequest13 represents the HelloRetryRequest handshake message for DTLS 1.3.
// The HelloRetryRequest is sent by the server when the ClientHello is acceptable but the server
// requires different or additional information to proceed with the handshake.
//
// Common use cases:
//   - Client's key_share extension doesn't include a group the server supports
//     (server responds with key_share extension containing SelectedGroup)
//   - Server needs to set a cookie for DoS protection
//     (server responds with cookie extension)
//
// The HelloRetryRequest uses the same structure as ServerHello but is distinguished by a special
// Random value (SHA-256 of "HelloRetryRequest").
//
// Per RFC 8446 Section 4.1.4:
//   - MUST contain 'supported_versions' extension
//   - SHOULD contain minimal set of extensions necessary for client to generate correct ClientHello
//   - MUST NOT contain extensions not offered by client (except optionally 'cookie')
//
// Example with key_share (most common use case):
//
//	selectedGroup := elliptic.X25519
//	hrr := &MessageHelloRetryRequest13{
//		Version:       protocol.Version{Major: 0xFE, Minor: 0xFD}, // DTLS 1.2 for compatibility
//		SessionID:     clientSessionID, // Echo from ClientHello
//		CipherSuiteID: 0x1301,          // Selected cipher suite
//		Extensions: []extension.Extension{
//			&extension.SupportedVersions{
//				Versions: []protocol.Version{{Major: 0xFE, Minor: 0xFC}}, // DTLS 1.3
//			},
//			&extension.KeyShare{
//				SelectedGroup: &selectedGroup, // Request client to use X25519
//			},
//		},
//	}
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4
type MessageHelloRetryRequest13 struct {
	// Version must be set to DTLS 1.2 (0xFEFD) for compatibility.
	// The actual protocol version is negotiated via the supported_versions extension.
	Version protocol.Version

	// SessionID echoes the value from the ClientHello.
	SessionID []byte

	// CipherSuiteID is the server's selected cipher suite.
	CipherSuiteID uint16

	// Extensions contains the extensions necessary for the client to generate
	// a correct second ClientHello. MUST contain 'supported_versions'.
	// SHOULD contain minimal set of extensions (e.g., key_share, cookie).
	// MUST NOT contain extensions not offered by the client (except 'cookie').
	Extensions []extension.Extension
}

const (
	helloRetryRequest13VersionFieldSize     = 2
	helloRetryRequest13SessionIDLengthSize  = 1
	helloRetryRequest13CipherSuiteLengthSize = 2
	helloRetryRequest13CompressionMethodSize = 1
	helloRetryRequest13MinSize              = helloRetryRequest13VersionFieldSize +
		RandomLength +
		helloRetryRequest13SessionIDLengthSize +
		helloRetryRequest13CipherSuiteLengthSize +
		helloRetryRequest13CompressionMethodSize
)

// Type returns the handshake message type.
// HelloRetryRequest uses TypeServerHello for wire compatibility.
func (m MessageHelloRetryRequest13) Type() Type {
	return TypeServerHello
}

// Marshal encodes the MessageHelloRetryRequest13 into its wire format.
//
// Wire format (identical to ServerHello):
//
//	[2 bytes]  version (legacy_version = 0xFEFD for DTLS 1.2)
//	[32 bytes] random (special HRR value: SHA-256 of "HelloRetryRequest")
//	[1 byte]   session_id length
//	[variable] session_id
//	[2 bytes]  cipher_suite
//	[1 byte]   compression_method (always 0x00 for TLS 1.3)
//	[2 bytes]  extensions length
//	[variable] extensions data
func (m *MessageHelloRetryRequest13) Marshal() ([]byte, error) {
	var b cryptobyte.Builder

	// Version (legacy_version)
	b.AddUint8(m.Version.Major)
	b.AddUint8(m.Version.Minor)

	// Random - use the special HelloRetryRequest value
	b.AddBytes(HelloRetryRequestRandomBytes[:])

	// SessionID with 1-byte length prefix
	if len(m.SessionID) > 255 {
		return nil, errLengthMismatch
	}
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.SessionID)
	})

	// CipherSuite
	b.AddUint16(m.CipherSuiteID)

	// CompressionMethod (always 0x00 for TLS 1.3)
	b.AddUint8(0x00)

	// Extensions
	extensionsData, err := extension.Marshal(m.Extensions)
	if err != nil {
		return nil, err
	}
	b.AddBytes(extensionsData)

	return b.Bytes()
}

// Unmarshal decodes the MessageHelloRetryRequest13 from its wire format.
func (m *MessageHelloRetryRequest13) Unmarshal(data []byte) error {
	// Validate minimum message size
	if len(data) < helloRetryRequest13MinSize {
		return errBufferTooSmall
	}

	s := cryptobyte.String(data)

	// Version
	if !s.ReadUint8(&m.Version.Major) || !s.ReadUint8(&m.Version.Minor) {
		return errBufferTooSmall
	}

	// Random - verify it's the HelloRetryRequest magic value
	var randomBytes [RandomLength]byte
	if !s.CopyBytes(randomBytes[:]) {
		return errBufferTooSmall
	}
	// Note: In production, you should verify randomBytes == HelloRetryRequestRandomBytes
	// to ensure this is actually a HelloRetryRequest and not a regular ServerHello.

	// SessionID with 1-byte length prefix
	var sessionIDData cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sessionIDData) {
		return errBufferTooSmall
	}
	m.SessionID = make([]byte, len(sessionIDData))
	copy(m.SessionID, sessionIDData)

	// CipherSuite
	if !s.ReadUint16(&m.CipherSuiteID) {
		return errBufferTooSmall
	}

	// CompressionMethod (must be 0x00 for TLS 1.3)
	var compressionMethod uint8
	if !s.ReadUint8(&compressionMethod) {
		return errBufferTooSmall
	}
	if compressionMethod != 0x00 {
		return errInvalidCompressionMethod
	}

	// Extensions (if any remaining data)
	if len(s) > 0 {
		extensions, err := extension.Unmarshal(s)
		if err != nil {
			return err
		}
		m.Extensions = extensions
	} else {
		m.Extensions = []extension.Extension{}
	}

	return nil
}

// IsHelloRetryRequest checks if a Random value matches the HelloRetryRequest magic value.
// This helper function can be used to distinguish HelloRetryRequest from ServerHello.
func IsHelloRetryRequest(random [RandomLength]byte) bool {
	return random == HelloRetryRequestRandomBytes
}

// IsHelloRetryRequestFromRandom checks if a Random struct contains the HelloRetryRequest magic value.
func IsHelloRetryRequestFromRandom(r Random) bool {
	return r.MarshalFixed() == HelloRetryRequestRandomBytes
}
