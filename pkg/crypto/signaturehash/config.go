// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package signaturehash

import "github.com/pion/dtls/v3/pkg/protocol"

// Option represents a configuration option for SelectSignatureScheme.
type Option func(*config)

// WithTLSProtocolVersion is an option to override
// the default TLS protocol version.
func WithTLSProtocolVersion(tlsVersion protocol.Version) Option {
	return func(s *config) { s.tlsVersion = tlsVersion }
}

// config is a configuration object built internally
// from defaults and given Options.
type config struct {
	tlsVersion protocol.Version
}

// newConfig returns a newly built config object with
// all given options applied.
func newConfig(opts ...Option) (*config, error) {
	cfg := &config{
		tlsVersion: protocol.Version1_2, // default to TLS 1.2
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate validates all fields in config are valid.
func (cfg *config) validate() error {
	if !protocol.IsSupportedVersion(cfg.tlsVersion) {
		return errInvalidProtocolVersion
	}

	return nil
}
