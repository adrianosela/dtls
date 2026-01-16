// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
)

// TestDTLS13HelloRetryRequestFlow tests the complete HelloRetryRequest flow.
// This is a stub test showing how HRR would be integrated into DTLS 1.3 handshake.
//
// TODO: Implement when DTLS 1.3 handshake and key derivation are complete.
func TestDTLS13HelloRetryRequestFlow(t *testing.T) {
	t.Skip("DTLS 1.3 handshake not yet implemented - blocked by key derivation")

	// Scenario: Client offers P-256, server prefers X25519
	// Expected: Server sends HRR with key_share extension requesting X25519

	// Create initial ClientHello with P-256 key share
	clientHello1 := &handshake.MessageClientHello{
		Version: protocol.Version1_2, // Legacy version
		SessionID: []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		},
		Extensions: []extension.Extension{
			&extension.SupportedVersions{
				Versions: []protocol.Version{protocol.Version1_3},
			},
			// Stub: key_share with P-256
		},
	}

	// Server determines HRR is needed
	needsHRR, reason := shouldSendHelloRetryRequest(nil, clientHello1, nil)
	assert.True(t, needsHRR)
	assert.Equal(t, "key_share", reason)

	// Server builds HelloRetryRequest
	hrr, alert, err := buildHelloRetryRequest(nil, clientHello1, reason, nil)
	assert.NoError(t, err)
	assert.Nil(t, alert)
	assert.NotNil(t, hrr)

	// Validate HRR structure
	assert.Equal(t, protocol.Version1_2, hrr.Version) // Legacy version
	assert.Equal(t, clientHello1.SessionID, hrr.SessionID)

	// HRR should have supported_versions and key_share
	var hasKeyShare, hasSupportedVersions bool
	for _, ext := range hrr.Extensions {
		switch ext.(type) {
		case *extension.KeyShare:
			hasKeyShare = true
		case *extension.SupportedVersions:
			hasSupportedVersions = true
		}
	}
	assert.True(t, hasKeyShare, "HRR must contain key_share")
	assert.True(t, hasSupportedVersions, "HRR must contain supported_versions")

	// Client receives HRR and validates it
	alert = validateHelloRetryRequest(clientHello1, hrr)
	assert.Nil(t, alert)

	// Client generates updated ClientHello
	clientHello2, err := retryClientHelloWithHRR(nil, clientHello1, hrr, nil)
	assert.NoError(t, err)
	assert.NotNil(t, clientHello2)

	// Verify updated ClientHello has X25519 key share
	assert.Equal(t, clientHello1.SessionID, clientHello2.SessionID)
}

// TestHelloRetryRequestKeyShareSelection tests that HRR correctly selects key share group.
//
// TODO: Implement when DTLS 1.3 is complete.
func TestHelloRetryRequestKeyShareSelection(t *testing.T) {
	t.Skip("DTLS 1.3 not yet implemented")

	tests := map[string]struct {
		clientGroups  []elliptic.Curve
		serverPrefers []elliptic.Curve
		expectHRR     bool
		expectedGroup elliptic.Curve
	}{
		"client and server match - no HRR": {
			clientGroups:  []elliptic.Curve{elliptic.X25519, elliptic.P256},
			serverPrefers: []elliptic.Curve{elliptic.X25519, elliptic.P256},
			expectHRR:     false,
		},
		"client offers P-256, server prefers X25519 - send HRR": {
			clientGroups:  []elliptic.Curve{elliptic.P256},
			serverPrefers: []elliptic.Curve{elliptic.X25519, elliptic.P256},
			expectHRR:     true,
			expectedGroup: elliptic.X25519,
		},
		"client offers X25519, server prefers P-384 - send HRR": {
			clientGroups:  []elliptic.Curve{elliptic.X25519},
			serverPrefers: []elliptic.Curve{elliptic.P384, elliptic.P256},
			expectHRR:     true,
			expectedGroup: elliptic.P384,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Stub: Test key share group selection logic
			_ = test
		})
	}
}

// TestHelloRetryRequestCookie tests HRR with cookie extension for DoS protection.
//
// TODO: Implement when DTLS 1.3 is complete.
func TestHelloRetryRequestCookie(t *testing.T) {
	t.Skip("DTLS 1.3 not yet implemented")

	// Scenario: Server under load, needs to verify client
	// Expected: Send HRR with cookie extension

	// Create ClientHello without cookie
	clientHello1 := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Extensions: []extension.Extension{
			&extension.SupportedVersions{
				Versions: []protocol.Version{protocol.Version1_3},
			},
		},
	}

	// Server decides to send HRR with cookie
	needsHRR, reason := shouldSendHelloRetryRequest(nil, clientHello1, nil)
	assert.True(t, needsHRR)
	assert.Equal(t, "cookie", reason)

	// HRR should contain cookie extension
	hrr, _, err := buildHelloRetryRequest(nil, clientHello1, reason, nil)
	assert.NoError(t, err)

	var hasCookie bool
	for _, ext := range hrr.Extensions {
		if _, ok := ext.(*extension.CookieExt); ok {
			hasCookie = true
		}
	}
	assert.True(t, hasCookie, "HRR should contain cookie extension")

	// Client must echo cookie in second ClientHello
	clientHello2, err := retryClientHelloWithHRR(nil, clientHello1, hrr, nil)
	assert.NoError(t, err)

	var clientHasCookie bool
	for _, ext := range clientHello2.Extensions {
		if _, ok := ext.(*extension.CookieExt); ok {
			clientHasCookie = true
		}
	}
	assert.True(t, clientHasCookie, "Updated ClientHello must echo cookie")
}

// TestHelloRetryRequestValidation tests RFC 8446 compliance validation.
//
// TODO: Implement when DTLS 1.3 is complete.
func TestHelloRetryRequestValidation(t *testing.T) {
	t.Skip("DTLS 1.3 not yet implemented")

	tests := map[string]struct {
		clientHello *handshake.MessageClientHello
		hrr         *handshake.MessageHelloRetryRequest13
		expectError bool
		description string
	}{
		"valid HRR with key_share": {
			// Valid: HRR contains only key_share and supported_versions
			expectError: false,
		},
		"invalid - missing supported_versions": {
			// Invalid: HRR must contain supported_versions
			expectError: true,
			description: "HRR must contain supported_versions extension",
		},
		"invalid - extension not offered by client": {
			// Invalid: HRR contains extension client didn't offer (except cookie)
			expectError: true,
			description: "HRR must not contain extensions not offered by client",
		},
		"invalid - no changes to ClientHello": {
			// Invalid: HRR doesn't result in any changes
			expectError: true,
			description: "HRR must result in changes to ClientHello",
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			alert := validateHelloRetryRequest(test.clientHello, test.hrr)
			if test.expectError {
				assert.NotNil(t, alert, test.description)
			} else {
				assert.Nil(t, alert)
			}
		})
	}
}
