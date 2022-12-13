package template

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

var BastionZeroIdentity = pkix.Name{
	Organization: []string{"BastionZero, Inc."},
	Country:      []string{"USA"},
	Locality:     []string{"Boston"},
	Province:     []string{"Massachusetts"},
}

const (
	Year = 24 * time.Hour * 365 // Helpful placeholder for now
)

func CA(identity pkix.Name, lifetime time.Duration) (*x509.Certificate, error) {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      identity,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(lifetime),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign, // because this is a CA, it needs to be able to sign
		// Lucie: revisit the below list https://security.stackexchange.com/questions/68491/recommended-key-usage-for-a-client-certificate
		// this ref seems to use it but others think they're superfluous: https://go.dev/src/crypto/tls/generate_cert.go
		// x509.KeyUsageDigitalSignature |
		// x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}, nil
}

func ServerCertificate(hostname string, lifetime time.Duration) (*x509.Certificate, error) {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(lifetime),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}, nil
}

func ClientCertificate(username string, lifetime time.Duration) (*x509.Certificate, error) {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: username,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(lifetime),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}, nil
}

func generateSerialNumber() (*big.Int, error) {
	// ref: https://go.dev/src/crypto/tls/generate_cert.go
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	if serialNumber, err := rand.Int(rand.Reader, serialNumberLimit); err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	} else {
		return serialNumber, nil
	}
}
