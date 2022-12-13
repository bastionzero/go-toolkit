package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/bastionzero/go-toolkit/certificate"
	"github.com/bastionzero/go-toolkit/certificate/ca"
	"github.com/bastionzero/go-toolkit/certificate/template"
)

type ServerCertificate struct {
	certficate *x509.Certificate
	privateKey *rsa.PrivateKey
}

func Generate(parent *ca.CA, hostname string, rsaKeyLength int) (*ServerCertificate, error) {
	// Check that parent is allowed to sign
	if parent.PrivateKey() == nil || parent.X509().KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("parent certificate cannot be used to sign certificates")
	}

	serverCert, err := template.ServerCertificate(hostname, template.Year)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new server certificate from our template: %s", err)
	}

	// generate rsa key pair
	certKey, err := rsa.GenerateKey(rand.Reader, rsaKeyLength)
	if err != nil {
		return nil, fmt.Errorf("we fucked up generating the key: %s", err)
	}

	// Sign the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, serverCert, parent.X509(), &certKey.PublicKey, parent.PrivateKey())
	if err != nil {
		return nil, fmt.Errorf("we fucked up generating the certificate: %s", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("golang fucked up and did not give us a der-encoded certficate: %s", err)
	}

	return &ServerCertificate{
		certficate: cert,
		privateKey: certKey,
	}, nil
}

func (s *ServerCertificate) PEM() (string, string, error) {
	certPEM, err := certificate.EncodeCertificatePEM(s.certficate)
	if err != nil {
		return "", "", err
	}

	keyPEM, err := certificate.EncodeRSAPrivateKeyPEM(s.privateKey)
	if err != nil {
		return "", "", err
	}

	return certPEM, keyPEM, nil
}
