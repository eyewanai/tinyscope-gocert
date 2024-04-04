package cert

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"gocert/internal/logger"
	"gocert/models"
	"strings"
)

// Certificate.Issuer
// https://pkg.go.dev/crypto/x509#Certificate.Issuer

func GetCert(domain string) ([]*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	domain = normalizeURL(domain)
	addr := fmt.Sprintf("%s:443", domain)
	// fmt.Println(addr)
	conn, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		logger.InfoLog.Printf("Can't connect to %s: %d", addr, err)
		return nil, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates

	return certs, nil
}

func ParseIssuer(issuer pkix.Name) models.Subject {
	orgName := ""
	countryName := ""
	if len(issuer.Organization) > 0 {
		orgName = issuer.Organization[0]
	}
	if len(issuer.Country) > 0 {
		countryName = issuer.Country[0]
	}
	return models.Subject{
		CommonName:       issuer.CommonName,
		OrganizationName: orgName,
		CountryName:      countryName,
	}
}

func ParseFingerprints(certRaw models.CertRaw) models.CertFingerprints {
	return models.CertFingerprints{
		SHA1:   SHA1Fingerprint(certRaw),
		SHA256: SHA256Fingerprint(certRaw),
	}
}

func ParseSAN(certificate *x509.Certificate) models.SAN {
	dnsNames := certificate.DNSNames
	san := models.SAN{DNS: make([]string, len(dnsNames))}
	copy(san.DNS, dnsNames)
	return san
}

func SHA256Fingerprint(data models.CertRaw) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func SHA1Fingerprint(data models.CertRaw) string {
	hash := sha1.Sum(data)
	return hex.EncodeToString(hash[:])
}

func ParseSigAlgorithm(certificate *x509.Certificate) models.SigAlgorithm {
	algorithm := certificate.SignatureAlgorithm
	value := hexSplit(certificate.Signature)

	return models.SigAlgorithm{
		Algorithm: algorithm.String(),
		Value:     value,
	}
}

func normalizeURL(input string) string {
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimSuffix(input, "/")

	return input
}

func hexSplit(input []byte) string {
	var result string
	for i, b := range input {
		if i > 0 {
			result += ":"
		}
		result += fmt.Sprintf("%02x", b)
	}
	return result
}
