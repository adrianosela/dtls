// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"encoding/binary"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
)

const (
	signatureAlgorithmsCertHeaderSize = 6
)

// SignatureAlgorithmsCert allows a Client/Server to indicate which signature algorithms
// may be used in digital signatures for X.509 certificates.
// This is separate from signature_algorithms which applies to handshake signatures.
//
// RFC 8446 Section 4.2.3:
// "TLS 1.2 implementations SHOULD also process this extension.
// If present, the signature_algorithms_cert extension SHALL be treated as being
// equivalent to signature_algorithms for the purposes of certificate chain validation."
//
// https://tools.ietf.org/html/rfc8446#section-4.2.3
type SignatureAlgorithmsCert struct {
	SignatureHashAlgorithms []signaturehash.Algorithm
}

// TypeValue returns the extension TypeValue.
func (s SignatureAlgorithmsCert) TypeValue() TypeValue {
	return SignatureAlgorithmsCertTypeValue
}

// Marshal encodes the extension.
// This supports hybrid encoding: TLS 1.3 PSS schemes are encoded as full uint16,
// while TLS 1.2 schemes use hash (high byte) + signature (low byte) encoding.
func (s *SignatureAlgorithmsCert) Marshal() ([]byte, error) {
	out := make([]byte, signatureAlgorithmsCertHeaderSize)

	binary.BigEndian.PutUint16(out, uint16(s.TypeValue()))
	binary.BigEndian.PutUint16(out[2:], uint16(2+(len(s.SignatureHashAlgorithms)*2))) //nolint:gosec // G115
	binary.BigEndian.PutUint16(out[4:], uint16(len(s.SignatureHashAlgorithms)*2))     //nolint:gosec // G115
	for _, v := range s.SignatureHashAlgorithms {
		// For PSS schemes (>= 0x0800), write the full uint16 SignatureScheme value
		// For other schemes, write hash (high byte) + signature (low byte) in TLS 1.2 style
		if v.Signature.IsPSS() {
			// TLS 1.3 PSS: full uint16 is the signature scheme
			scheme := uint16(v.Signature)
			out = append(out, byte(scheme>>8), byte(scheme&0xFF))
		} else {
			// TLS 1.2 style: hash byte + signature byte
			out = append(out, byte(v.Hash), byte(v.Signature))
		}
	}

	return out, nil
}

// Unmarshal populates the extension from encoded data.
// This supports hybrid encoding: detects TLS 1.3 PSS schemes (0x0804-0x080b)
// and handles them as full uint16, while TLS 1.2 schemes use byte-split encoding.
func (s *SignatureAlgorithmsCert) Unmarshal(data []byte) error {
	if len(data) < signatureAlgorithmsCertHeaderSize {
		return errBufferTooSmall
	} else if TypeValue(binary.BigEndian.Uint16(data)) != s.TypeValue() {
		return errInvalidExtensionType
	}

	algorithmCount := int(binary.BigEndian.Uint16(data[4:]) / 2)
	s.SignatureHashAlgorithms = []signaturehash.Algorithm{}
	if signatureAlgorithmsCertHeaderSize+(algorithmCount*2) > len(data) {
		return errLengthMismatch
	}
	for i := 0; i < algorithmCount; i++ {
		// Read 2 bytes as a uint16 scheme value
		offset := signatureAlgorithmsCertHeaderSize + (i * 2)
		scheme := binary.BigEndian.Uint16(data[offset:])

		// Parse the signature scheme (handles both TLS 1.2 and TLS 1.3 PSS encoding)
		supportedHashAlgorithm, supportedSignatureAlgorithm := parseSignatureScheme(scheme, data, offset)

		// Validate both hash and signature algorithms
		if _, ok := hash.Algorithms()[supportedHashAlgorithm]; ok {
			if _, ok := signature.Algorithms()[supportedSignatureAlgorithm]; ok {
				s.SignatureHashAlgorithms = append(s.SignatureHashAlgorithms, signaturehash.Algorithm{
					Hash:      supportedHashAlgorithm,
					Signature: supportedSignatureAlgorithm,
				})
			}
		}
	}

	return nil
}
