# signature_algorithms_cert Extension Examples

Demonstrates certificate signature algorithm validation with explicit allow/deny flags.

## Directory Structure

```
.
├── dial
│   └── main.go
├── listen
│   └── main.go
└── sample-certs
    ├── ecdsa
    │   ├── ca-cert.pem
    │   ├── server-chain.pem
    │   └── server-key.pem
    └── rsa
        ├── ca-cert.pem
        ├── server-chain.pem
        └── server-key.pem
```

## Client Flags

All signature algorithms are **denied by default**. Use flags to allow specific algorithms:

```
-allow-any              Allow any certificate signature algorithm
-allow-ecdsa-p256       Allow ECDSA P-256 SHA256
-allow-ecdsa-p384       Allow ECDSA P-384 SHA384
-allow-ecdsa-p521       Allow ECDSA P-521 SHA512
-allow-pss-sha256       Allow RSA-PSS SHA256
-allow-pss-sha384       Allow RSA-PSS SHA384
-allow-pss-sha512       Allow RSA-PSS SHA512
-allow-pkcs1-sha256     Allow RSA PKCS1 SHA256
-allow-pkcs1-sha384     Allow RSA PKCS1 SHA384
-allow-pkcs1-sha512     Allow RSA PKCS1 SHA512
-allow-ed25519          Allow Ed25519
```

## Success Case Example (RSA with RSA allowed)

**Terminal 1:**
```bash
go run listen/main.go -key sample-certs/rsa/server-key.pem -cert sample-certs/rsa/server-chain.pem
```

**Terminal 2:**
```bash
go run dial/main.go -ca-cert sample-certs/rsa/ca-cert.pem -allow-pkcs1-sha256
```

## Failure Case Example (RSA with RSA not allowed)

**Terminal 1:**
```bash
go run listen/main.go -key sample-certs/rsa/server-key.pem -cert sample-certs/rsa/server-chain.pem
```

**Terminal 2:**
```bash
go run dial/main.go -ca-cert sample-certs/rsa/ca-cert.pem -allow-ecdsa-p256
```

## Success Case Example (ECDSA with ECDSA allowed)

**Terminal 1:**
```bash
go run listen/main.go -key sample-certs/ecdsa/server-key.pem -cert sample-certs/ecdsa/server-chain.pem
```

**Terminal 2:**
```bash
go run dial/main.go -ca-cert sample-certs/ecdsa/ca-cert.pem -allow-ecdsa-p256
```

## Failure Case Example (ECDSA with ECDSA not allowed)

**Terminal 1:**
```bash
go run listen/main.go -key sample-certs/ecdsa/server-key.pem -cert sample-certs/ecdsa/server-chain.pem
```

**Terminal 2:**
```bash
go run dial/main.go -ca-cert sample-certs/ecdsa/ca-cert.pem -allow-pkcs1-sha256
```
