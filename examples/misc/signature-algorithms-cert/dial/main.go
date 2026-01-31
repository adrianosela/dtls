// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/examples/util"
)

func main() { //nolint:cyclop
	caCert := flag.String("ca-cert", "", "Path to CA certificate (required)")
	addr := flag.String("addr", "127.0.0.1:4444", "Address to connect to")

	// Special flag to allow any signature algorithm
	allowAny := flag.Bool("allow-any", false, "Allow any certificate signature algorithm")

	// Explicit allow flags for each algorithm
	allowECDSAP256 := flag.Bool("allow-ecdsa-p256", false, "Allow ECDSA P-256 SHA256")
	allowECDSAP384 := flag.Bool("allow-ecdsa-p384", false, "Allow ECDSA P-384 SHA384")
	allowECDSAP521 := flag.Bool("allow-ecdsa-p521", false, "Allow ECDSA P-521 SHA512")
	allowPSSWithSHA256 := flag.Bool("allow-pss-sha256", false, "Allow RSA-PSS SHA256")
	allowPSSWithSHA384 := flag.Bool("allow-pss-sha384", false, "Allow RSA-PSS SHA384")
	allowPSSWithSHA512 := flag.Bool("allow-pss-sha512", false, "Allow RSA-PSS SHA512")
	allowPKCS1SHA256 := flag.Bool("allow-pkcs1-sha256", false, "Allow RSA PKCS1 SHA256")
	allowPKCS1SHA384 := flag.Bool("allow-pkcs1-sha384", false, "Allow RSA PKCS1 SHA384")
	allowPKCS1SHA512 := flag.Bool("allow-pkcs1-sha512", false, "Allow RSA PKCS1 SHA512")
	allowEd25519 := flag.Bool("allow-ed25519", false, "Allow Ed25519")

	flag.Parse()

	if *caCert == "" {
		fmt.Fprintf(os.Stderr, "Error: -ca-cert flag is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Load CA certificate as trusted root
	rootCertificate, err := util.LoadCertificate(*caCert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load CA certificate: %v\n", err)
		os.Exit(1)
	}
	certPool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(rootCertificate.Certificate[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse certificate: %v\n", err)
		os.Exit(1)
	}
	certPool.AddCert(cert)

	udpAddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to resolve address: %v\n", err)
		os.Exit(1)
	}

	// Build signature schemes list based on flags
	var schemes []tls.SignatureScheme

	if *allowAny {
		// Leave schemes empty/nil to allow any certificate signature algorithm
		fmt.Println("✅ Allowing ANY certificate signature algorithm")
	} else {
		if *allowECDSAP256 {
			schemes = append(schemes, tls.ECDSAWithP256AndSHA256)
			fmt.Println("✅ ECDSA P-256 SHA256")
		}
		if *allowECDSAP384 {
			schemes = append(schemes, tls.ECDSAWithP384AndSHA384)
			fmt.Println("✅ ECDSA P-384 SHA384")
		}
		if *allowECDSAP521 {
			schemes = append(schemes, tls.ECDSAWithP521AndSHA512)
			fmt.Println("✅ ECDSA P-521 SHA512")
		}
		if *allowPSSWithSHA256 {
			schemes = append(schemes, tls.PSSWithSHA256)
			fmt.Println("✅ RSA-PSS SHA256")
		}
		if *allowPSSWithSHA384 {
			schemes = append(schemes, tls.PSSWithSHA384)
			fmt.Println("✅ RSA-PSS SHA384")
		}
		if *allowPSSWithSHA512 {
			schemes = append(schemes, tls.PSSWithSHA512)
			fmt.Println("✅ RSA-PSS SHA512")
		}
		if *allowPKCS1SHA256 {
			schemes = append(schemes, tls.PKCS1WithSHA256)
			fmt.Println("✅ RSA PKCS1 SHA256")
		}
		if *allowPKCS1SHA384 {
			schemes = append(schemes, tls.PKCS1WithSHA384)
			fmt.Println("✅ RSA PKCS1 SHA384")
		}
		if *allowPKCS1SHA512 {
			schemes = append(schemes, tls.PKCS1WithSHA512)
			fmt.Println("✅ RSA PKCS1 SHA512")
		}
		if *allowEd25519 {
			schemes = append(schemes, tls.Ed25519)
			fmt.Println("✅ Ed25519")
		}

		if len(schemes) == 0 {
			fmt.Fprintln(os.Stderr, "ERROR: No signature algorithms allowed. Use -allow-* flags to specify allowed algorithms.")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Available flags:")
			fmt.Fprintln(os.Stderr, "  -allow-any              Allow any certificate signature algorithm")
			fmt.Fprintln(os.Stderr, "  -allow-ecdsa-p256       Allow ECDSA P-256 SHA256")
			fmt.Fprintln(os.Stderr, "  -allow-ecdsa-p384       Allow ECDSA P-384 SHA384")
			fmt.Fprintln(os.Stderr, "  -allow-ecdsa-p521       Allow ECDSA P-521 SHA512")
			fmt.Fprintln(os.Stderr, "  -allow-pss-sha256       Allow RSA-PSS SHA256")
			fmt.Fprintln(os.Stderr, "  -allow-pss-sha384       Allow RSA-PSS SHA384")
			fmt.Fprintln(os.Stderr, "  -allow-pss-sha512       Allow RSA-PSS SHA512")
			fmt.Fprintln(os.Stderr, "  -allow-pkcs1-sha256     Allow RSA PKCS1 SHA256")
			fmt.Fprintln(os.Stderr, "  -allow-pkcs1-sha384     Allow RSA PKCS1 SHA384")
			fmt.Fprintln(os.Stderr, "  -allow-pkcs1-sha512     Allow RSA PKCS1 SHA512")
			fmt.Fprintln(os.Stderr, "  -allow-ed25519          Allow Ed25519")
			os.Exit(1)
		}
	}

	config := &dtls.Config{
		ExtendedMasterSecret:        dtls.RequireExtendedMasterSecret,
		RootCAs:                     certPool,
		CertificateSignatureSchemes: schemes,
	}

	fmt.Println("\nConnecting to:", udpAddr)
	fmt.Println("CA cert:", *caCert)

	conn, err := dtls.Dial("udp", udpAddr, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed to connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close() //nolint:gosec,errcheck

	fmt.Println("\n✅ Connected successfully!")
	fmt.Println("Type messages to send (Ctrl+C to exit)")

	go func() {
		buffer := make([]byte, 8192)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				if errors.Is(err, io.EOF) {
					fmt.Fprintf(os.Stderr, "\nConnection error: %v\n", err)
				}
				os.Exit(0)
			}
			fmt.Printf("Received: %s\n", buffer[:n])
		}
	}()

	buffer := make([]byte, 8192)
	for {
		n, err := os.Stdin.Read(buffer)
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Fprintf(os.Stderr, "Read error: %v\n", err)
			}

			return
		}

		_, err = conn.Write(buffer[:n])
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nWrite error: %v\n", err)
			os.Exit(1) //nolint:gocritic
		}
	}
}
