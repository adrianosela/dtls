// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"

	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// DTLS 1.3 Handshake Flow Stubs
//
// DTLS 1.3 uses a different handshake flow than DTLS 1.2:
//
// Initial handshake:
//   ClientHello
//     + key_share
//     + supported_versions
//   ServerHello OR HelloRetryRequest
//   {EncryptedExtensions}
//   {CertificateRequest*}
//   {Certificate*}
//   {CertificateVerify*}
//   {Finished}
//   [Application Data*]
//
// HelloRetryRequest flow:
//   ClientHello (1)
//     + key_share (e.g., P-256)
//   HelloRetryRequest
//     + key_share (selected_group: X25519)
//     + cookie*
//   ClientHello (2)
//     + key_share (X25519)
//     + cookie*
//   ServerHello
//   ...
//
// https://datatracker.ietf.org/doc/html/rfc9147

// handleClientHelloDTLS13 processes a ClientHello for DTLS 1.3.
// Returns either ServerHello or HelloRetryRequest.
//
// TODO: Implement when DTLS 1.3 key derivation is complete (blocked by #738).
func handleClientHelloDTLS13(
	_ context.Context,
	_ *State,
	_ *handshake.MessageClientHello,
	_ *handshakeConfig,
) (handshake.Message, *alert.Alert, error) {
	// Stub: Check if we can proceed with ClientHello's key_share
	// If not, return HelloRetryRequest with preferred group
	return nil, nil, errNotImplemented
}

// shouldSendHelloRetryRequest determines if we need to send a HelloRetryRequest.
// Returns true if:
//   - Client's key_share doesn't match server's preference
//   - Server needs to set a cookie for DoS protection
//   - Other DTLS 1.3-specific reasons
//
// TODO: Implement when DTLS 1.3 handshake logic is complete.
func shouldSendHelloRetryRequest(
	_ *State,
	_ *handshake.MessageClientHello,
	_ *handshakeConfig,
) (bool, string) {
	// Stub: Logic to determine if HRR is needed
	return false, ""
}

// buildHelloRetryRequest constructs a HelloRetryRequest message.
//
// TODO: Implement when DTLS 1.3 handshake logic is complete.
func buildHelloRetryRequest(
	_ *State,
	_ *handshake.MessageClientHello,
	_ string, // reason: "key_share", "cookie", etc.
	_ *handshakeConfig,
) (*handshake.MessageHelloRetryRequest13, *alert.Alert, error) {
	// Stub: Build HRR with appropriate extensions
	return nil, nil, errNotImplemented
}

// handleHelloRetryRequest processes a received HelloRetryRequest on the client side.
// Updates state to send a new ClientHello with the requested parameters.
//
// TODO: Implement when DTLS 1.3 client handshake is complete.
func handleHelloRetryRequest(
	_ context.Context,
	_ *State,
	_ *handshake.MessageHelloRetryRequest13,
	_ *handshakeConfig,
) (*handshake.MessageClientHello, *alert.Alert, error) {
	// Stub: Validate HRR and prepare updated ClientHello
	return nil, nil, errNotImplemented
}

// validateHelloRetryRequest validates an HRR message according to RFC 8446 Section 4.1.4.
// Checks:
//   - MUST contain 'supported_versions' extension
//   - MUST NOT contain extensions not offered by client (except 'cookie')
//   - Selected cipher suite matches one offered by client
//   - HRR would result in a change to the ClientHello
//
// TODO: Implement when DTLS 1.3 handshake validation is complete.
func validateHelloRetryRequest(
	_ *handshake.MessageClientHello,
	_ *handshake.MessageHelloRetryRequest13,
) *alert.Alert {
	// Stub: RFC 8446 compliance validation
	return nil
}

// retryClientHelloWithHRR generates a new ClientHello based on HelloRetryRequest.
// The new ClientHello must:
//   - Include the same session_id
//   - Use the key_share group requested by HRR (if any)
//   - Include the cookie from HRR (if any)
//   - Otherwise match the original ClientHello
//
// TODO: Implement when DTLS 1.3 handshake is complete.
func retryClientHelloWithHRR(
	_ *State,
	_ *handshake.MessageClientHello, // original
	_ *handshake.MessageHelloRetryRequest13,
	_ *handshakeConfig,
) (*handshake.MessageClientHello, error) {
	// Stub: Generate updated ClientHello
	return nil, errNotImplemented
}
