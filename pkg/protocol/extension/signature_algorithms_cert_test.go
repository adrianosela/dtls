// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"reflect"
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
)

func TestSignatureAlgorithmsCert(t *testing.T) {
	rawSignatureAlgorithmsCert := []byte{
		0x00, 0x32, // Extension type: signature_algorithms_cert (50)
		0x00, 0x08, // Extension length: 8 bytes
		0x00, 0x06, // Signature Hash Algorithms Length: 6 bytes
		0x04, 0x03, // SHA256, ECDSA
		0x05, 0x03, // SHA384, ECDSA
		0x06, 0x03, // SHA512, ECDSA
	}
	parsedSignatureAlgorithmsCert := &SignatureAlgorithmsCert{
		SignatureHashAlgorithms: []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.ECDSA},
			{Hash: hash.SHA384, Signature: signature.ECDSA},
			{Hash: hash.SHA512, Signature: signature.ECDSA},
		},
	}

	raw, err := parsedSignatureAlgorithmsCert.Marshal()
	if err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(raw, rawSignatureAlgorithmsCert) {
		t.Errorf("SignatureAlgorithmsCert marshal: got %#v, want %#v", raw, rawSignatureAlgorithmsCert)
	}

	ext := &SignatureAlgorithmsCert{}
	if err := ext.Unmarshal(rawSignatureAlgorithmsCert); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(ext, parsedSignatureAlgorithmsCert) {
		t.Errorf("SignatureAlgorithmsCert unmarshal: got %#v, want %#v", ext, parsedSignatureAlgorithmsCert)
	}
}

func TestSignatureAlgorithmsCertTypeValue(t *testing.T) {
	ext := &SignatureAlgorithmsCert{}
	if ext.TypeValue() != SignatureAlgorithmsCertTypeValue {
		t.Errorf("SignatureAlgorithmsCert TypeValue: got %d, want %d", ext.TypeValue(), SignatureAlgorithmsCertTypeValue)
	}
	if ext.TypeValue() != 50 {
		t.Errorf("SignatureAlgorithmsCert TypeValue: got %d, want 50", ext.TypeValue())
	}
}

func TestSignatureAlgorithmsCertRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		ext  *SignatureAlgorithmsCert
	}{
		{
			name: "Empty",
			ext: &SignatureAlgorithmsCert{
				SignatureHashAlgorithms: []signaturehash.Algorithm{},
			},
		},
		{
			name: "Single algorithm",
			ext: &SignatureAlgorithmsCert{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.RSA},
				},
			},
		},
		{
			name: "Multiple algorithms",
			ext: &SignatureAlgorithmsCert{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.RSA},
					{Hash: hash.SHA384, Signature: signature.ECDSA},
					{Hash: hash.SHA512, Signature: signature.Ed25519},
				},
			},
		},
		{
			name: "RSA-PSS algorithms",
			ext: &SignatureAlgorithmsCert{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.RSA_PSS_RSAE_SHA256},
					{Hash: hash.SHA384, Signature: signature.RSA_PSS_RSAE_SHA384},
					{Hash: hash.SHA512, Signature: signature.RSA_PSS_RSAE_SHA512},
				},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.ext.Marshal()
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}

			parsed := &SignatureAlgorithmsCert{}
			if err := parsed.Unmarshal(raw); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}

			if !reflect.DeepEqual(parsed, tc.ext) {
				t.Errorf("Round trip failed: got %#v, want %#v", parsed, tc.ext)
			}
		})
	}
}
