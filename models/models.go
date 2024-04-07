package models

import (
	"crypto/x509/pkix"
	"time"
)

type CertIssuer pkix.Name

// Certificate.Raw []byte Complete ASN.1 DER content (certificate, signature algorithm and signature).
// https://pkg.go.dev/crypto/x509#Certificate.Raw
type CertRaw []byte

type Subject struct {
	CommonName       string
	OrganizationName string
	CountryName      string
}

type CertFingerprints struct {
	SHA256 string
	SHA1   string
}

// Subject Alternative Names
type SAN struct {
	DNS []string
}

type SigAlgorithm struct {
	Algorithm string
	Value     string
}

type Validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type CertificateMetadata struct {
	DomainName              string
	SerialNumber            string
	Validity                Validity
	CertificateFingerprints CertFingerprints
	SignatureAlgorithm      SigAlgorithm
	SubjectAlternativeNames SAN
	Issuer                  Subject
}
