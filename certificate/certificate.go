package certificate

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func EncodeRSAPrivateKeyPEM(key *rsa.PrivateKey) (string, error) {
	keyPEM := new(bytes.Buffer)
	err := pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return keyPEM.String(), fmt.Errorf("failed to pem-encode RSA private key: %s", err)
}

func EncodeCertificatePEM(cert *x509.Certificate) (string, error) {
	certPEM := new(bytes.Buffer)
	err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return certPEM.String(), fmt.Errorf("failed to pem-encode x509 certificate: %s", err)
}
