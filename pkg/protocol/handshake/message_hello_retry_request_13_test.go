// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"crypto/sha256"
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHelloRetryRequestRandomBytes(t *testing.T) {
	// Verify that the HelloRetryRequest random value matches the expected SHA-256 hash
	// of "HelloRetryRequest"
	expectedHash := sha256.Sum256([]byte("HelloRetryRequest"))

	assert.Equal(t, 32, len(HelloRetryRequestRandomBytes))
	assert.Equal(t, expectedHash[:], HelloRetryRequestRandomBytes[:])

	// Verify against the RFC 8446 value
	// CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
	// C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
	expectedBytes := []byte{
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
		0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
		0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
	}
	assert.Equal(t, expectedBytes, HelloRetryRequestRandomBytes[:])
}

func TestMessageHelloRetryRequest13_Type(t *testing.T) {
	m := &MessageHelloRetryRequest13{}
	// HelloRetryRequest uses TypeServerHello for wire compatibility
	assert.Equal(t, TypeServerHello, m.Type())
}

func TestMessageHelloRetryRequest13_Marshal(t *testing.T) {
	tests := map[string]struct {
		msg    *MessageHelloRetryRequest13
		expErr error
	}{
		"valid - minimal message": {
			msg: &MessageHelloRetryRequest13{
				Version:       protocol.Version{Major: 0xFE, Minor: 0xFD}, // DTLS 1.2
				SessionID:     []byte{},
				CipherSuiteID: 0x1301, // TLS_AES_128_GCM_SHA256
				Extensions: []extension.Extension{
					&extension.SupportedVersions{
						Versions: []protocol.Version{{Major: 0xFE, Minor: 0xFC}}, // DTLS 1.3
					},
				},
			},
		},
		"valid - with session ID": {
			msg: &MessageHelloRetryRequest13{
				Version:       protocol.Version{Major: 0xFE, Minor: 0xFD},
				SessionID:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				CipherSuiteID: 0x1302, // TLS_AES_256_GCM_SHA384
				Extensions: []extension.Extension{
					&extension.SupportedVersions{
						Versions: []protocol.Version{{Major: 0xFE, Minor: 0xFC}},
					},
				},
			},
		},
		"valid - with multiple extensions": {
			msg: &MessageHelloRetryRequest13{
				Version:       protocol.Version{Major: 0xFE, Minor: 0xFD},
				SessionID:     []byte{0x01, 0x02},
				CipherSuiteID: 0x1301,
				Extensions: []extension.Extension{
					&extension.SupportedVersions{
						Versions: []protocol.Version{{Major: 0xFE, Minor: 0xFC}},
					},
					&extension.CookieExt{Cookie: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
				},
			},
		},
		"invalid - session ID too long": {
			msg: &MessageHelloRetryRequest13{
				Version:       protocol.Version{Major: 0xFE, Minor: 0xFD},
				SessionID:     make([]byte, 256), // Max is 255
				CipherSuiteID: 0x1301,
				Extensions:    []extension.Extension{},
			},
			expErr: errLengthMismatch,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			data, err := test.msg.Marshal()

			if test.expErr != nil {
				assert.ErrorIs(t, err, test.expErr)
			} else {
				require.NoError(t, err)

				// Verify the random value is correctly set
				assert.Equal(t, HelloRetryRequestRandomBytes[:], data[2:2+RandomLength])

				// Round-trip test
				unmarshaled := &MessageHelloRetryRequest13{}
				err = unmarshaled.Unmarshal(data)
				require.NoError(t, err)

				assert.Equal(t, test.msg.Version, unmarshaled.Version)
				assert.Equal(t, test.msg.SessionID, unmarshaled.SessionID)
				assert.Equal(t, test.msg.CipherSuiteID, unmarshaled.CipherSuiteID)
				assert.Equal(t, len(test.msg.Extensions), len(unmarshaled.Extensions))
			}
		})
	}
}

func TestMessageHelloRetryRequest13_Unmarshal(t *testing.T) {
	tests := map[string]struct {
		data   []byte
		expMsg *MessageHelloRetryRequest13
		expErr error
	}{
		"valid - minimal message": {
			data: func() []byte {
				// Version (DTLS 1.2)
				data := []byte{0xFE, 0xFD}
				// Random (HelloRetryRequest magic value)
				data = append(data, HelloRetryRequestRandomBytes[:]...)
				// SessionID length (0)
				data = append(data, 0x00)
				// CipherSuite
				data = append(data, 0x13, 0x01)
				// CompressionMethod (0x00)
				data = append(data, 0x00)
				// Extensions (empty)
				return data
			}(),
			expMsg: &MessageHelloRetryRequest13{
				Version:       protocol.Version{Major: 0xFE, Minor: 0xFD},
				SessionID:     []byte{},
				CipherSuiteID: 0x1301,
				Extensions:    []extension.Extension{},
			},
		},
		"valid - with session ID": {
			data: func() []byte {
				data := []byte{0xFE, 0xFD}
				data = append(data, HelloRetryRequestRandomBytes[:]...)
				// SessionID length (4) + data
				data = append(data, 0x04, 0x01, 0x02, 0x03, 0x04)
				data = append(data, 0x13, 0x02) // CipherSuite
				data = append(data, 0x00)       // CompressionMethod
				return data
			}(),
			expMsg: &MessageHelloRetryRequest13{
				Version:       protocol.Version{Major: 0xFE, Minor: 0xFD},
				SessionID:     []byte{0x01, 0x02, 0x03, 0x04},
				CipherSuiteID: 0x1302,
				Extensions:    []extension.Extension{},
			},
		},
		"invalid - buffer too small": {
			data:   []byte{0xFE},
			expErr: errBufferTooSmall,
		},
		"invalid - compression method not zero": {
			data: func() []byte {
				data := []byte{0xFE, 0xFD}
				data = append(data, HelloRetryRequestRandomBytes[:]...)
				data = append(data, 0x00)       // SessionID length
				data = append(data, 0x13, 0x01) // CipherSuite
				data = append(data, 0x01)       // CompressionMethod (invalid - must be 0x00)
				return data
			}(),
			expErr: errInvalidCompressionMethod,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			msg := &MessageHelloRetryRequest13{}
			err := msg.Unmarshal(test.data)

			if test.expErr != nil {
				assert.ErrorIs(t, err, test.expErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.expMsg.Version, msg.Version)
				assert.Equal(t, test.expMsg.SessionID, msg.SessionID)
				assert.Equal(t, test.expMsg.CipherSuiteID, msg.CipherSuiteID)
				assert.Equal(t, len(test.expMsg.Extensions), len(msg.Extensions))
			}
		})
	}
}

func TestMessageHelloRetryRequest13_MarshalUnmarshal(t *testing.T) {
	// Create a HelloRetryRequest with supported_versions and cookie extensions
	originalMsg := &MessageHelloRetryRequest13{
		Version:       protocol.Version{Major: 0xFE, Minor: 0xFD},
		SessionID:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		CipherSuiteID: 0x1301, // TLS_AES_128_GCM_SHA256
		Extensions: []extension.Extension{
			&extension.SupportedVersions{
				Versions: []protocol.Version{{Major: 0xFE, Minor: 0xFC}}, // DTLS 1.3
			},
			&extension.CookieExt{
				Cookie: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE},
			},
		},
	}

	// Marshal
	data, err := originalMsg.Marshal()
	require.NoError(t, err)

	// Verify the HelloRetryRequest magic value is present
	assert.Equal(t, HelloRetryRequestRandomBytes[:], data[2:2+RandomLength])

	// Unmarshal
	parsedMsg := &MessageHelloRetryRequest13{}
	err = parsedMsg.Unmarshal(data)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, originalMsg.Version, parsedMsg.Version)
	assert.Equal(t, originalMsg.SessionID, parsedMsg.SessionID)
	assert.Equal(t, originalMsg.CipherSuiteID, parsedMsg.CipherSuiteID)
	assert.Equal(t, len(originalMsg.Extensions), len(parsedMsg.Extensions))
}

func TestIsHelloRetryRequest(t *testing.T) {
	// Test with the actual HelloRetryRequest magic value
	assert.True(t, IsHelloRetryRequest(HelloRetryRequestRandomBytes))

	// Test with a different random value
	var differentRandom [RandomLength]byte
	for i := range differentRandom {
		differentRandom[i] = byte(i)
	}
	assert.False(t, IsHelloRetryRequest(differentRandom))

	// Test with an all-zero random value
	var zeroRandom [RandomLength]byte
	assert.False(t, IsHelloRetryRequest(zeroRandom))
}

func TestIsHelloRetryRequestFromRandom(t *testing.T) {
	// Create a Random struct with the HelloRetryRequest magic value
	var hrrRandom Random
	hrrRandom.UnmarshalFixed(HelloRetryRequestRandomBytes)
	assert.True(t, IsHelloRetryRequestFromRandom(hrrRandom))

	// Create a Random struct with a different value
	var normalRandom Random
	err := normalRandom.Populate()
	require.NoError(t, err)
	// This should not equal the HelloRetryRequest magic value
	// (statistically extremely unlikely)
	assert.False(t, IsHelloRetryRequestFromRandom(normalRandom))
}

func TestMessageHelloRetryRequest13_WithKeyShareExtension(t *testing.T) {
	// Test HelloRetryRequest with key_share extension (most common use case)
	// This is sent when the server doesn't support the client's offered key share group
	// and needs to request a different group (e.g., X25519)
	selectedGroup := elliptic.X25519
	msg := &MessageHelloRetryRequest13{
		Version:       protocol.Version{Major: 0xFE, Minor: 0xFD},
		SessionID:     []byte{0x11, 0x22, 0x33, 0x44},
		CipherSuiteID: 0x1301,
		Extensions: []extension.Extension{
			&extension.SupportedVersions{
				Versions: []protocol.Version{{Major: 0xFE, Minor: 0xFC}},
			},
			&extension.KeyShare{
				SelectedGroup: &selectedGroup, // HelloRetryRequest mode
			},
		},
	}

	// Marshal and unmarshal
	data, err := msg.Marshal()
	require.NoError(t, err)

	parsedMsg := &MessageHelloRetryRequest13{}
	err = parsedMsg.Unmarshal(data)
	require.NoError(t, err)

	assert.Equal(t, msg.Version, parsedMsg.Version)
	assert.Equal(t, msg.SessionID, parsedMsg.SessionID)
	assert.Equal(t, msg.CipherSuiteID, parsedMsg.CipherSuiteID)
	assert.Equal(t, 2, len(parsedMsg.Extensions))

	// Verify key_share extension with SelectedGroup
	var foundKeyShare bool
	for _, ext := range parsedMsg.Extensions {
		if ks, ok := ext.(*extension.KeyShare); ok {
			foundKeyShare = true
			require.NotNil(t, ks.SelectedGroup)
			assert.Equal(t, selectedGroup, *ks.SelectedGroup)
		}
	}
	assert.True(t, foundKeyShare, "key_share extension not found")
}

func TestMessageHelloRetryRequest13_EmptySessionID(t *testing.T) {
	// Test with empty session ID (valid in DTLS 1.3)
	msg := &MessageHelloRetryRequest13{
		Version:       protocol.Version{Major: 0xFE, Minor: 0xFD},
		SessionID:     []byte{},
		CipherSuiteID: 0x1302,
		Extensions: []extension.Extension{
			&extension.SupportedVersions{
				Versions: []protocol.Version{{Major: 0xFE, Minor: 0xFC}},
			},
		},
	}

	data, err := msg.Marshal()
	require.NoError(t, err)

	parsedMsg := &MessageHelloRetryRequest13{}
	err = parsedMsg.Unmarshal(data)
	require.NoError(t, err)

	assert.Equal(t, []byte{}, parsedMsg.SessionID)
}

func FuzzMessageHelloRetryRequest13(f *testing.F) {
	// Seed with valid minimal message
	f.Add(func() []byte {
		data := []byte{0xFE, 0xFD}
		data = append(data, HelloRetryRequestRandomBytes[:]...)
		data = append(data, 0x00)       // SessionID length
		data = append(data, 0x13, 0x01) // CipherSuite
		data = append(data, 0x00)       // CompressionMethod
		return data
	}())

	// Seed with valid message with session ID
	f.Add(func() []byte {
		data := []byte{0xFE, 0xFD}
		data = append(data, HelloRetryRequestRandomBytes[:]...)
		data = append(data, 0x04, 0x01, 0x02, 0x03, 0x04) // SessionID
		data = append(data, 0x13, 0x02)                   // CipherSuite
		data = append(data, 0x00)                         // CompressionMethod
		return data
	}())

	// Seed with invalid data
	f.Add([]byte{0x00})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(_ *testing.T, data []byte) {
		msg := &MessageHelloRetryRequest13{}
		_ = msg.Unmarshal(data)
	})
}
