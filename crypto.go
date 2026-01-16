// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
)

type ecdsaSignature struct {
	R, S *big.Int
}

func valueKeyMessage(clientRandom, serverRandom, publicKey []byte, namedCurve elliptic.Curve) []byte {
	serverECDHParams := make([]byte, 4)
	serverECDHParams[0] = 3 // named curve
	binary.BigEndian.PutUint16(serverECDHParams[1:], uint16(namedCurve))
	serverECDHParams[3] = byte(len(publicKey))

	plaintext := []byte{}
	plaintext = append(plaintext, clientRandom...)
	plaintext = append(plaintext, serverRandom...)
	plaintext = append(plaintext, serverECDHParams...)
	plaintext = append(plaintext, publicKey...)

	return plaintext
}

// If the client provided a "signature_algorithms" extension, then all
// certificates provided by the server MUST be signed by a
// hash/signature algorithm pair that appears in that extension
//
// https://tools.ietf.org/html/rfc5246#section-7.4.2
func generateKeySignature(
	clientRandom, serverRandom, publicKey []byte,
	namedCurve elliptic.Curve,
	signer crypto.Signer,
	hashAlgorithm hash.Algorithm,
	signatureAlgorithm signature.Algorithm,
) ([]byte, error) {
	msg := valueKeyMessage(clientRandom, serverRandom, publicKey, namedCurve)
	switch signer.Public().(type) {
	case ed25519.PublicKey:
		// https://crypto.stackexchange.com/a/55483
		return signer.Sign(rand.Reader, msg, crypto.Hash(0))
	case *ecdsa.PublicKey:
		hashed := hashAlgorithm.Digest(msg)

		return signer.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHash())
	case *rsa.PublicKey:
		hashed := hashAlgorithm.Digest(msg)

		// Use RSA-PSS if the signature algorithm is PSS
		if signatureAlgorithm.IsPSS() {
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashAlgorithm.CryptoHash(),
			}

			return signer.Sign(rand.Reader, hashed, pssOpts)
		}

		// Otherwise use PKCS#1 v1.5
		return signer.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHash())
	}

	return nil, errKeySignatureGenerateUnimplemented
}

//nolint:dupl,cyclop
func verifyKeySignature(
	message, remoteKeySignature []byte,
	hashAlgorithm hash.Algorithm,
	signatureAlgorithm signature.Algorithm,
	rawCertificates [][]byte,
) error {
	if len(rawCertificates) == 0 {
		return errLengthMismatch
	}
	certificate, err := x509.ParseCertificate(rawCertificates[0])
	if err != nil {
		return err
	}

	switch pubKey := certificate.PublicKey.(type) {
	case ed25519.PublicKey:
		if ok := ed25519.Verify(pubKey, message, remoteKeySignature); !ok {
			return errKeySignatureMismatch
		}

		return nil
	case *ecdsa.PublicKey:
		ecdsaSig := &ecdsaSignature{}
		if _, err := asn1.Unmarshal(remoteKeySignature, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errInvalidECDSASignature
		}
		hashed := hashAlgorithm.Digest(message)
		if !ecdsa.Verify(pubKey, hashed, ecdsaSig.R, ecdsaSig.S) {
			return errKeySignatureMismatch
		}

		return nil
	case *rsa.PublicKey:
		hashed := hashAlgorithm.Digest(message)

		// Use RSA-PSS verification if the signature algorithm is PSS
		if signatureAlgorithm.IsPSS() {
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashAlgorithm.CryptoHash(),
			}
			if err := rsa.VerifyPSS(pubKey, hashAlgorithm.CryptoHash(), hashed, remoteKeySignature, pssOpts); err != nil {
				return errKeySignatureMismatch
			}

			return nil
		}

		// Otherwise use PKCS#1 v1.5
		if rsa.VerifyPKCS1v15(pubKey, hashAlgorithm.CryptoHash(), hashed, remoteKeySignature) != nil {
			return errKeySignatureMismatch
		}

		return nil
	}

	return errKeySignatureVerifyUnimplemented
}

// If the server has sent a CertificateRequest message, the client MUST send the Certificate
// message.  The ClientKeyExchange message is now sent, and the content
// of that message will depend on the public key algorithm selected
// between the ClientHello and the ServerHello.  If the client has sent
// a certificate with signing ability, a digitally-signed
// CertificateVerify message is sent to explicitly verify possession of
// the private key in the certificate.
// https://tools.ietf.org/html/rfc5246#section-7.3
func generateCertificateVerify(
	handshakeBodies []byte,
	signer crypto.Signer,
	hashAlgorithm hash.Algorithm,
	signatureAlgorithm signature.Algorithm,
) ([]byte, error) {
	if _, ok := signer.Public().(ed25519.PublicKey); ok {
		// https://pkg.go.dev/crypto/ed25519#PrivateKey.Sign
		// Sign signs the given message with priv. Ed25519 performs two passes over
		// messages to be signed and therefore cannot handle pre-hashed messages.
		return signer.Sign(rand.Reader, handshakeBodies, crypto.Hash(0))
	}

	hashed := hashAlgorithm.Digest(handshakeBodies)

	switch signer.Public().(type) {
	case *ecdsa.PublicKey:
		return signer.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHash())
	case *rsa.PublicKey:
		// Use RSA-PSS if the signature algorithm is PSS
		if signatureAlgorithm.IsPSS() {
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashAlgorithm.CryptoHash(),
			}

			return signer.Sign(rand.Reader, hashed, pssOpts)
		}

		// Otherwise use PKCS#1 v1.5
		return signer.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHash())
	}

	return nil, errInvalidSignatureAlgorithm
}

//nolint:dupl,cyclop
func verifyCertificateVerify(
	handshakeBodies []byte,
	hashAlgorithm hash.Algorithm,
	signatureAlgorithm signature.Algorithm,
	remoteKeySignature []byte,
	rawCertificates [][]byte,
) error {
	if len(rawCertificates) == 0 {
		return errLengthMismatch
	}
	certificate, err := x509.ParseCertificate(rawCertificates[0])
	if err != nil {
		return err
	}

	switch pubKey := certificate.PublicKey.(type) {
	case ed25519.PublicKey:
		if ok := ed25519.Verify(pubKey, handshakeBodies, remoteKeySignature); !ok {
			return errKeySignatureMismatch
		}

		return nil
	case *ecdsa.PublicKey:
		ecdsaSig := &ecdsaSignature{}
		if _, err := asn1.Unmarshal(remoteKeySignature, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errInvalidECDSASignature
		}
		hash := hashAlgorithm.Digest(handshakeBodies)
		if !ecdsa.Verify(pubKey, hash, ecdsaSig.R, ecdsaSig.S) {
			return errKeySignatureMismatch
		}

		return nil
	case *rsa.PublicKey:
		hash := hashAlgorithm.Digest(handshakeBodies)

		// Use RSA-PSS verification if the signature algorithm is PSS
		if signatureAlgorithm.IsPSS() {
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashAlgorithm.CryptoHash(),
			}
			if err := rsa.VerifyPSS(pubKey, hashAlgorithm.CryptoHash(), hash, remoteKeySignature, pssOpts); err != nil {
				return errKeySignatureMismatch
			}

			return nil
		}

		// Otherwise use PKCS#1 v1.5
		if rsa.VerifyPKCS1v15(pubKey, hashAlgorithm.CryptoHash(), hash, remoteKeySignature) != nil {
			return errKeySignatureMismatch
		}

		return nil
	}

	return errKeySignatureVerifyUnimplemented
}

func loadCerts(rawCertificates [][]byte) ([]*x509.Certificate, error) {
	if len(rawCertificates) == 0 {
		return nil, errLengthMismatch
	}

	certs := make([]*x509.Certificate, 0, len(rawCertificates))
	for _, rawCert := range rawCertificates {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func verifyClientCert(rawCertificates [][]byte, roots *x509.CertPool, certSignatureSchemes []signaturehash.Algorithm) (chains [][]*x509.Certificate, err error) {
	certificate, err := loadCerts(rawCertificates)
	if err != nil {
		return nil, err
	}
	intermediateCAPool := x509.NewCertPool()
	for _, cert := range certificate[1:] {
		intermediateCAPool.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		CurrentTime:   time.Now(),
		Intermediates: intermediateCAPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	chains, err = certificate[0].Verify(opts)
	if err != nil {
		return nil, err
	}

	// Validate certificate signature algorithms if specified
	if len(certSignatureSchemes) > 0 && len(chains) > 0 {
		if err := validateCertificateSignatureAlgorithms(chains[0], certSignatureSchemes); err != nil {
			return nil, err
		}
	}

	return chains, nil
}

func verifyServerCert(
	rawCertificates [][]byte,
	roots *x509.CertPool,
	serverName string,
	certSignatureSchemes []signaturehash.Algorithm,
) (chains [][]*x509.Certificate, err error) {
	certificate, err := loadCerts(rawCertificates)
	if err != nil {
		return nil, err
	}
	intermediateCAPool := x509.NewCertPool()
	for _, cert := range certificate[1:] {
		intermediateCAPool.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		CurrentTime:   time.Now(),
		DNSName:       serverName,
		Intermediates: intermediateCAPool,
	}

	chains, err = certificate[0].Verify(opts)
	if err != nil {
		return nil, err
	}

	// Validate certificate signature algorithms if specified
	if len(certSignatureSchemes) > 0 && len(chains) > 0 {
		if err := validateCertificateSignatureAlgorithms(chains[0], certSignatureSchemes); err != nil {
			return nil, err
		}
	}

	return chains, nil
}

// extractSignatureAlgorithmFromCert maps x509.SignatureAlgorithm to our internal signaturehash.Algorithm type.
// This allows us to validate that certificate chain signatures use allowed signature algorithms.
func extractSignatureAlgorithmFromCert(cert *x509.Certificate) (signaturehash.Algorithm, error) {
	var h hash.Algorithm
	var s signature.Algorithm

	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS:
		h = hash.SHA256
		s = signature.RSA
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS:
		h = hash.SHA384
		s = signature.RSA
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
		h = hash.SHA512
		s = signature.RSA
	case x509.ECDSAWithSHA256:
		h = hash.SHA256
		s = signature.ECDSA
	case x509.ECDSAWithSHA384:
		h = hash.SHA384
		s = signature.ECDSA
	case x509.ECDSAWithSHA512:
		h = hash.SHA512
		s = signature.ECDSA
	case x509.PureEd25519:
		h = hash.None // Ed25519 doesn't use a separate hash
		s = signature.Ed25519
	case x509.SHA1WithRSA:
		h = hash.SHA1
		s = signature.RSA
	case x509.ECDSAWithSHA1:
		h = hash.SHA1
		s = signature.ECDSA
	default:
		return signaturehash.Algorithm{}, errInvalidSignatureAlgorithm
	}

	return signaturehash.Algorithm{Hash: h, Signature: s}, nil
}

// validateCertificateSignatureAlgorithms validates that all certificates in the chain
// use signature algorithms that are in the allowed list. This implements the
// signature_algorithms_cert extension validation per RFC 8446 Section 4.2.3.
func validateCertificateSignatureAlgorithms(
	certs []*x509.Certificate,
	allowedAlgorithms []signaturehash.Algorithm,
) error {
	if len(allowedAlgorithms) == 0 {
		// No restrictions specified
		return nil
	}

	// Validate each certificate's signature algorithm (except the root, which we trust)
	for i := 0; i < len(certs)-1; i++ {
		cert := certs[i]
		certAlg, err := extractSignatureAlgorithmFromCert(cert)
		if err != nil {
			return err
		}

		// Check if this algorithm is in the allowed list
		found := false
		for _, allowed := range allowedAlgorithms {
			if certAlg.Hash == allowed.Hash && certAlg.Signature == allowed.Signature {
				found = true
				break
			}
		}

		if !found {
			return errInvalidCertificateSignatureAlgorithm
		}
	}

	return nil
}
