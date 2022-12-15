/*
ref: https://medium.com/@shaneutt/create-sign-x509-certificates-in-golang-8ac4ae49f903
ref: https://www.crunchydata.com/blog/ssl-certificate-authentication-postgresql-docker-containers
ref: https://fenixara.com/golang-connecting-to-posgres-using-ssl/
*/
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/bastionzero/go-toolkit/certificate"
	"github.com/bastionzero/go-toolkit/certificate/template"

	"github.com/bastionzero/keysplitting"
)

const (
	rsaKeyLength = 4096
)

type CA struct {
	certficate *x509.Certificate
	splitKey   *keysplitting.PrivateKeyShard
	privateKey *rsa.PrivateKey
}

func Generate() (*CA, *keysplitting.PrivateKeyShard, error) {
	// Generate our certificate authority template
	ca, err := template.CA(template.BastionZeroIdentity, template.Year)
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
		splitKey:   shards[0],
		privateKey: certKey,
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
		splitKey:   key,
	}, nil
}

func (c *CA) SplitPrivateKey() *keysplitting.PrivateKeyShard {
	return c.splitKey
}

func (c *CA) PrivateKey() *rsa.PrivateKey {
	return c.privateKey
}

func (c *CA) X509() *x509.Certificate {
	return c.certficate
}

func (c *CA) PEM() (string, string, error) {
	certPEM, err := certificate.EncodeCertificatePEM(c.certficate)
	if err != nil {
		return "", "", err
	}

	agentKeyPem, err := c.splitKey.EncodePEM()
	if err != nil {
		return "", "", fmt.Errorf("failed to pem-encode split private key: %s", err)
	}

	return certPEM, agentKeyPem, nil
}

func (c *CA) GenerateServerCertificate(hostname string) (string, string, error) {
	// Check that parent is allowed to sign
	if c.PrivateKey() == nil {
		return "", "", fmt.Errorf("this certificate no longer has access to its full key and can longer issue certificates unilaterally")
	}

	serverCert, err := template.ServerCertificate(hostname, template.Year)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate new server certificate from our template: %s", err)
	}

	// generate rsa key pair
	certKey, err := rsa.GenerateKey(rand.Reader, rsaKeyLength)
	if err != nil {
		return "", "", fmt.Errorf("we fucked up generating the key: %s", err)
	}

	// Sign the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, serverCert, c.X509(), &certKey.PublicKey, c.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("we fucked up generating the certificate: %s", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return "", "", fmt.Errorf("golang fucked up and did not give us a der-encoded certficate: %s", err)
	}

	certPEM, err := certificate.EncodeCertificatePEM(cert)
	if err != nil {
		return "", "", err
	}

	keyPEM, err := certificate.EncodeRSAPrivateKeyPEM(certKey)
	if err != nil {
		return "", "", err
	}

	return certPEM, keyPEM, nil
}
