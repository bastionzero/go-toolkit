/*
ref: https://medium.com/@shaneutt/create-sign-x509-certificates-in-golang-8ac4ae49f903
ref: https://www.crunchydata.com/blog/ssl-certificate-authentication-postgresql-docker-containers
ref: https://fenixara.com/golang-connecting-to-posgres-using-ssl/
*/
package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"gotoolkit/certificate/template"

	"github.com/bastionzero/keysplitting"
)

const (
	rsaKeyLength = 4096
)

type CA struct {
	certficate *x509.Certificate
	privateKey *keysplitting.SplitPrivateKey
	fullKey    *rsa.PrivateKey
}

func Generate() (*CA, *keysplitting.SplitPrivateKey, error) {
	// Generate our certificate authority template
	ca, err := template.CA()
	if err != nil {
		return nil, nil, fmt.Errorf("we fucked up generating a new CA from our template: %s", err)
	}

	// generate rsa key pair
	certKey, err := rsa.GenerateKey(rand.Reader, rsaKeyLength)
	if err != nil {
		return nil, nil, fmt.Errorf("we fucked up generating the key: %s", err)
	}

	shards, err := keysplitting.SplitD(certKey, 2, keysplitting.Addition)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to split key: %s", err)
	}

	// Sign the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &certKey.PublicKey, certKey)
	if err != nil {
		return nil, nil, fmt.Errorf("we fucked up generating the certificate: %s", err)
	}

	certificate, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("golang fucked up and did not give us a der-encoded certficate: %s", err)
	}

	return &CA{
		certficate: certificate,
		privateKey: shards[0],
		fullKey:    certKey,
	}, shards[1], nil
}

func Load(caPEM string, keyPEM string) (*CA, error) {
	// Convert our pem back into a certificate
	block, _ := pem.Decode([]byte(caPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("golang fucked up and did not give us a der-encoded certficate: %s", err)
	}

	key, err := keysplitting.DecodePEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("bad split private key pem: %s", err)
	}

	return &CA{
		certficate: certificate,
		privateKey: key,
	}, nil
}

func (c *CA) PrivateKey() *keysplitting.SplitPrivateKey {
	return c.privateKey
}

func (c *CA) X509() *x509.Certificate {
	return c.certficate
}

func (c *CA) PEM() string {
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.certficate.Raw,
	})

	return certPEM.String()
}

func (c *CA) GenerateServerCertificate() (string, string, error) {
	if c.fullKey == nil {
		return "", "", fmt.Errorf("the certificate does not have access to its complete signing key and cannot generate certificates on its own")
	}

	serverCert, err := template.ServerCertificate("localhost")
	if err != nil {
		return "", "", fmt.Errorf("failed to generate new server certificate from our template: %s", err)
	}

	// generate rsa key pair
	certKey, err := rsa.GenerateKey(rand.Reader, rsaKeyLength)
	if err != nil {
		return "", "", fmt.Errorf("we fucked up generating the key: %s", err)
	}

	// Sign the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, serverCert, c.X509(), &certKey.PublicKey, c.fullKey)
	if err != nil {
		return "", "", fmt.Errorf("we fucked up generating the certificate: %s", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return "", "", fmt.Errorf("golang fucked up and did not give us a der-encoded certficate: %s", err)
	}

	return encodeCertificatePEM(cert), encodeRSAPrivateKeyPEM(certKey), nil
}

func encodeRSAPrivateKeyPEM(key *rsa.PrivateKey) string {
	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return keyPEM.String()
}

func encodeCertificatePEM(cert *x509.Certificate) string {
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return certPEM.String()
}
