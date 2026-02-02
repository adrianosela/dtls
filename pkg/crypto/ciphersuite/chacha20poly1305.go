// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	chachaTagLength   = 16
	chachaNonceLength = 12
)

// ChaCha20Poly1305 Provides an API to Encrypt/Decrypt DTLS 1.2 Packets.
type ChaCha20Poly1305 struct {
	aead *aead
}

// NewChaCha20Poly1305 creates a DTLS ChaCha20-Poly1305 Cipher.
func NewChaCha20Poly1305(localKey, localWriteIV, remoteKey, remoteWriteIV []byte) (*ChaCha20Poly1305, error) {
	localChaCha20Poly1305, err := chacha20poly1305.New(localKey)
	if err != nil {
		return nil, err
	}

	remoteChaCha20Poly1305, err := chacha20poly1305.New(remoteKey)
	if err != nil {
		return nil, err
	}

	return &ChaCha20Poly1305{
		aead: newAEAD(
			localChaCha20Poly1305,
			localWriteIV,
			remoteChaCha20Poly1305,
			remoteWriteIV,
			chachaNonceLength,
			chachaTagLength,
		),
	}, nil
}

// Encrypt encrypts a DTLS RecordLayer message.
func (c *ChaCha20Poly1305) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	return c.aead.encrypt(pkt, raw)
}

// Decrypt decrypts a DTLS RecordLayer message.
func (c *ChaCha20Poly1305) Decrypt(header recordlayer.Header, in []byte) ([]byte, error) {
	return c.aead.decrypt(header, in)
}
