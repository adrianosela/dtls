// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/examples/util"
)

func main() {
	serverKey := flag.String("key", "", "Path to server private key (required)")
	serverCert := flag.String("cert", "", "Path to server certificate (required)")
	addr := flag.String("addr", "127.0.0.1:4444", "Address to listen on")
	flag.Parse()

	if *serverKey == "" || *serverCert == "" {
		fmt.Fprintf(os.Stderr, "Error: -key and -cert flags are required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	certificate, err := util.LoadKeyAndCertificate(*serverKey, *serverCert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load certificate: %v\n", err)
		os.Exit(1)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", *addr)
	util.Check(err)

	config := &dtls.Config{
		Certificates:         []tls.Certificate{certificate},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	listener, err := dtls.Listen("udp", udpAddr, config)
	util.Check(err)
	defer func() { util.Check(listener.Close()) }()

	fmt.Println("Server listening on:", udpAddr)
	fmt.Println("Serving cert:", *serverCert)

	hub := util.NewHub()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Println("Accept error:", err)

				continue
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			dtlsConn, ok := conn.(*dtls.Conn)
			if ok {
				if err := dtlsConn.HandshakeContext(ctx); err != nil {
					fmt.Println("Handshake failed:", err)
					cancel()
					conn.Close() //nolint:gosec,errcheck

					continue
				}
				fmt.Println("Client connected!")
			}
			cancel()

			hub.Register(conn)
		}
	}()

	hub.Chat()
}
