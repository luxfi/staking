// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package staking

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// LoadTLSCertFromBytes parses a TLS certificate from PEM-encoded key and cert bytes.
func LoadTLSCertFromBytes(keyBytes, certBytes []byte) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed creating cert: %w", err)
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed parsing cert: %w", err)
	}
	return &cert, nil
}

// LoadTLSCertFromFiles loads a TLS certificate from key and cert files.
func LoadTLSCertFromFiles(keyPath, certPath string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed parsing cert: %w", err)
	}
	return &cert, nil
}
