// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandshakeUnmarshalHelloRetryRequest tests that Handshake.Unmarshal
// correctly distinguishes HelloRetryRequest from ServerHello based on the
// magic random value.
func TestHandshakeUnmarshalHelloRetryRequest(t *testing.T) {
	selectedGroup := elliptic.X25519

	// Create a HelloRetryRequest message
	hrr := &MessageHelloRetryRequest13{
		Version:       protocol.Version{Major: 0xFE, Minor: 0xFD},
		SessionID:     []byte{0x01, 0x02, 0x03, 0x04},
		CipherSuiteID: 0x1301,
		Extensions: []extension.Extension{
			&extension.SupportedVersions{
				Versions: []protocol.Version{{Major: 0xFE, Minor: 0xFC}},
			},
			&extension.KeyShare{
				SelectedGroup: &selectedGroup,
			},
		},
	}

	// Marshal HelloRetryRequest into a Handshake
	hrrMsg, err := hrr.Marshal()
	require.NoError(t, err)

	// Create a handshake header
	header := Header{
		Type:           TypeServerHello, // HRR uses ServerHello type
		Length:         uint32(len(hrrMsg)),
		MessageSequence: 0,
		FragmentOffset: 0,
		FragmentLength: uint32(len(hrrMsg)),
	}

	headerBytes, err := header.Marshal()
	require.NoError(t, err)

	handshakeBytes := append(headerBytes, hrrMsg...)

	// Unmarshal the handshake
	h := &Handshake{}
	err = h.Unmarshal(handshakeBytes)
	require.NoError(t, err)

	// Verify it was unmarshaled as HelloRetryRequest13, not ServerHello
	parsedHRR, ok := h.Message.(*MessageHelloRetryRequest13)
	require.True(t, ok, "Expected MessageHelloRetryRequest13, got %T", h.Message)
	assert.NotNil(t, parsedHRR)

	// Verify the fields
	assert.Equal(t, hrr.Version, parsedHRR.Version)
	assert.Equal(t, hrr.SessionID, parsedHRR.SessionID)
	assert.Equal(t, hrr.CipherSuiteID, parsedHRR.CipherSuiteID)
	assert.Equal(t, 2, len(parsedHRR.Extensions))
}

// TestHandshakeUnmarshalServerHello tests that Handshake.Unmarshal
// correctly identifies a regular ServerHello (not HelloRetryRequest).
func TestHandshakeUnmarshalServerHello(t *testing.T) {
	// Create a regular ServerHello with a normal random value
	serverHello := &MessageServerHello{
		Version: protocol.Version{Major: 0xFE, Minor: 0xFD},
		SessionID: []byte{0x01, 0x02, 0x03, 0x04},
		CipherSuiteID: new(uint16),
		CompressionMethod: &protocol.CompressionMethod{ID: 0},
		Extensions: []extension.Extension{
			&extension.SupportedVersions{
				Versions: []protocol.Version{{Major: 0xFE, Minor: 0xFD}},
			},
		},
	}
	*serverHello.CipherSuiteID = 0x1301

	// Populate with a normal (non-HRR) random value
	err := serverHello.Random.Populate()
	require.NoError(t, err)

	// Marshal ServerHello into a Handshake
	shMsg, err := serverHello.Marshal()
	require.NoError(t, err)

	// Create a handshake header
	header := Header{
		Type:           TypeServerHello,
		Length:         uint32(len(shMsg)),
		MessageSequence: 0,
		FragmentOffset: 0,
		FragmentLength: uint32(len(shMsg)),
	}

	headerBytes, err := header.Marshal()
	require.NoError(t, err)

	handshakeBytes := append(headerBytes, shMsg...)

	// Unmarshal the handshake
	h := &Handshake{}
	err = h.Unmarshal(handshakeBytes)
	require.NoError(t, err)

	// Verify it was unmarshaled as ServerHello, not HelloRetryRequest13
	parsedSH, ok := h.Message.(*MessageServerHello)
	require.True(t, ok, "Expected MessageServerHello, got %T", h.Message)
	assert.NotNil(t, parsedSH)

	// Verify the fields
	assert.Equal(t, serverHello.Version, parsedSH.Version)
	assert.Equal(t, serverHello.SessionID, parsedSH.SessionID)
	assert.Equal(t, *serverHello.CipherSuiteID, *parsedSH.CipherSuiteID)
}

// TestIsHelloRetryRequestBytes tests the helper function that detects HRR from raw bytes.
func TestIsHelloRetryRequestBytes(t *testing.T) {
	tests := map[string]struct {
		data   []byte
		expect bool
	}{
		"valid HRR magic value": {
			data: func() []byte {
				// Version (2 bytes) + HRR magic random (32 bytes)
				data := []byte{0xFE, 0xFD}
				data = append(data, HelloRetryRequestRandomBytes[:]...)
				return data
			}(),
			expect: true,
		},
		"regular ServerHello random": {
			data: func() []byte {
				// Version (2 bytes) + different random (32 bytes)
				data := []byte{0xFE, 0xFD}
				var random Random
				_ = random.Populate()
				randomBytes := random.MarshalFixed()
				data = append(data, randomBytes[:]...)
				return data
			}(),
			expect: false,
		},
		"buffer too small": {
			data:   []byte{0xFE},
			expect: false,
		},
		"empty buffer": {
			data:   []byte{},
			expect: false,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			result := isHelloRetryRequestBytes(test.data)
			assert.Equal(t, test.expect, result)
		})
	}
}

// TestHandshakeMarshalHelloRetryRequest tests that HelloRetryRequest can be marshaled
// through the Handshake wrapper.
func TestHandshakeMarshalHelloRetryRequest(t *testing.T) {
	selectedGroup := elliptic.X25519

	hrr := &MessageHelloRetryRequest13{
		Version:       protocol.Version{Major: 0xFE, Minor: 0xFD},
		SessionID:     []byte{0x11, 0x22, 0x33, 0x44},
		CipherSuiteID: 0x1302,
		Extensions: []extension.Extension{
			&extension.SupportedVersions{
				Versions: []protocol.Version{{Major: 0xFE, Minor: 0xFC}},
			},
			&extension.KeyShare{
				SelectedGroup: &selectedGroup,
			},
		},
	}

	// Marshal through Handshake
	h := &Handshake{
		Header: Header{
			MessageSequence: 1,
		},
		Message: hrr,
	}

	data, err := h.Marshal()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify the type is set to ServerHello (HRR uses ServerHello type)
	assert.Equal(t, TypeServerHello, Type(data[0]))

	// Unmarshal and verify
	parsedH := &Handshake{}
	err = parsedH.Unmarshal(data)
	require.NoError(t, err)

	parsedHRR, ok := parsedH.Message.(*MessageHelloRetryRequest13)
	require.True(t, ok)
	assert.Equal(t, hrr.SessionID, parsedHRR.SessionID)
	assert.Equal(t, hrr.CipherSuiteID, parsedHRR.CipherSuiteID)
}
