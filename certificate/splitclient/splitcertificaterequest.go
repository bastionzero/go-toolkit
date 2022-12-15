/*
Lines in this file taken from source code have references to the original lines
*/
package splitclient

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

	"github.com/bastionzero/go-toolkit/certificate"
	"github.com/bastionzero/keysplitting"
)

var (
	hashFunc = crypto.SHA256

	// ref: https://cs.opensource.google/go/go/+/refs/tags/go1.19.4:src/crypto/x509/x509.go;l=1403-1407;drc=7c7cd56870ba617f964014fa4694e9b61e29cf97
	privKeyAlgo = pkix.AlgorithmIdentifier{
		Algorithm:  oidSignatureSHA256WithRSA,
		Parameters: asn1.NullRawValue,
	}

	// ref: https://cs.opensource.google/go/go/+/refs/tags/go1.19.4:src/crypto/x509/x509.go;l=94-97;drc=fe67a21625ee811897077b32d4e75566ef74c6c4
	pubKeyAlgo = pkix.AlgorithmIdentifier{
		Algorithm: oidPublicKeyRSA,
		// This is a NULL parameters value which is required by
		// RFC 3279, Section 2.3.1.
		Parameters: asn1.NullRawValue,
	}
)

// This structure reflects the ASN.1 structure of X.509 certificates
type SplitClientCertificate struct {
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

func (c *SplitClientCertificate) Bytes() ([]byte, error) {
	return asn1.Marshal(*c)
}

func (c *SplitClientCertificate) X509() (*x509.Certificate, error) {
	certBytes, err := c.Bytes()
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certBytes)
}

func (s *SplitClientCertificate) PEM() (string, error) {
	if xcert, err := s.X509(); err != nil {
		return "", err
	} else {
		return certificate.EncodeCertificatePEM(xcert)
	}
}

func Generate(rand io.Reader, template, parent *x509.Certificate, pub *rsa.PublicKey, priv *keysplitting.PrivateKeyShard) (*SplitClientCertificate, error) {
	if err := checkClaims(template); err != nil {
		return nil, fmt.Errorf("provided certificate template did not conform to RFC standards: %s", err)
	}

	tbs, err := buildPreSignedCertificate(template, parent, pub)
	if err != nil {
		return nil, fmt.Errorf("failed to build certificate to be signed: %s", err)
	}

	if hashFunc == 0 {
		return nil, fmt.Errorf("no hash function was specified")
	}

	// Hash the contents of our to-be-signed certificate
	signed := tbs.Raw
	h := hashFunc.New()
	h.Write(signed)
	signed = h.Sum(nil)

	signature, err := keysplitting.SignFirst(rand, priv, hashFunc, signed)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %s", err)
	}

	return &SplitClientCertificate{
		*tbs,
		privKeyAlgo,
		asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	}, nil
}

func (s *SplitClientCertificate) VerifySignature(pub *rsa.PublicKey) error {
	// Check the signature to ensure the crypto.Signer behaved correctly.
	if err := checkSignature(x509.SHA256WithRSA, s.TBSCertificate.Raw, s.SignatureValue.Bytes, pub, true); err != nil {
		return fmt.Errorf("x509: signature over certificate returned by signer is invalid: %w", err)
	}
	return nil
}

func (s *SplitClientCertificate) Sign(rand io.Reader, parent *x509.Certificate, pub *rsa.PublicKey, priv *keysplitting.PrivateKeyShard) error {
	if hashFunc == 0 {
		return fmt.Errorf("no hash function was specified")
	}

	// Hash the contents of our to-be-signed certificate
	signed := s.TBSCertificate.Raw
	h := hashFunc.New()
	h.Write(signed)
	signed = h.Sum(nil)

	signature, err := keysplitting.SignNext(rand, priv, hashFunc, signed, s.SignatureValue.Bytes)
	if err != nil {
		return fmt.Errorf("failed to additionally sign our certificate: %s", err)
	}

	s.SignatureValue = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}

	return nil
}

func checkClaims(template *x509.Certificate) error {
	if template.SerialNumber == nil {
		return errors.New("x509: no SerialNumber given")
	}

	// RFC 5280 Section 4.1.2.2: serial number must positive
	//
	// We _should_ also restrict serials to <= 20 octets, but it turns out a lot of people
	// get this wrong, in part because the encoding can itself alter the length of the
	// serial. For now we accept these non-conformant serials.
	if template.SerialNumber.Sign() == -1 {
		return errors.New("x509: serial number must be positive")
	}

	if template.BasicConstraintsValid && !template.IsCA && template.MaxPathLen != -1 && (template.MaxPathLen != 0 || template.MaxPathLenZero) {
		return errors.New("x509: only CAs are allowed to specify MaxPathLen")
	}

	return nil
}

func buildPreSignedCertificate(template, parent *x509.Certificate, pub *rsa.PublicKey) (*tbsCertificate, error) {
	publicKeyBytes := x509.MarshalPKCS1PublicKey(pub)

	asn1Issuer, err := subjectBytes(parent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse parent certificate: %s", err)
	}

	asn1Subject, err := subjectBytes(template)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template certificate: %s", err)
	}

	authorityKeyId := template.AuthorityKeyId
	if !bytes.Equal(asn1Issuer, asn1Subject) && len(parent.SubjectKeyId) > 0 {
		authorityKeyId = parent.SubjectKeyId
	}

	subjectKeyId := template.SubjectKeyId
	if len(subjectKeyId) == 0 && template.IsCA {
		// SubjectKeyId generated using method 1 in RFC 5280, Section 4.2.1.2:
		//   (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
		//   value of the BIT STRING subjectPublicKey (excluding the tag,
		//   length, and number of unused bits).
		h := sha1.Sum(publicKeyBytes)
		subjectKeyId = h[:]
	}

	extensions, err := buildCertExtensions(template, bytes.Equal(asn1Subject, emptyASN1Subject), authorityKeyId, subjectKeyId)
	if err != nil {
		return nil, err
	}

	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}
	tbs := &tbsCertificate{
		Version:            2,
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: privKeyAlgo,
		Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
		Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:          publicKeyInfo{nil, pubKeyAlgo, encodedPublicKey},
		Extensions:         extensions,
	}

	tbsBytes, err := asn1.Marshal(*tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to encode our to-be-signed certificate: %s", err)
	}
	tbs.Raw = tbsBytes

	return tbs, nil
}
