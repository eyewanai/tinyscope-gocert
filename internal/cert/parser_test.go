package cert

import (
	"gocert/models"
	"testing"
)

func TestGetCert(t *testing.T) {
	domain := "example.com"
	_, err := GetCert(domain)
	if err != nil {
		t.Fatalf("Can't get certificate for %s", domain)
	}

}
func TestParseSAN(t *testing.T) {
	want := models.SAN{
		DNS: []string{"www.example.com", "example.net", "example.edu",
			"example.com", "example.org", "www.example.com",
			"www.example.edu", "www.example.net"},
	}
	domain := "example.com"
	certificates, _ := GetCert(domain)
	certificate := certificates[0]
	san := ParseSAN(certificate)

	if len(san.DNS) != len(want.DNS) {
		t.Errorf("Length of DNS slices mismatched: got %d, want %d", len(san.DNS), len(want.DNS))
	}
}

func TestParseSigAlgorith(t *testing.T) {
	want := models.SigAlgorithm{
		Algorithm: "SHA256-RSA",
		Value:     `04:e1:6e:02:3e:0d:e3:23:46:f4:e3:96:35:05:93:35:22:02:0b:84:5d:e2:73:86:d4:74:4f:fc:1b:27:af:3e:ca:ad:c3:ce:46:d6:fa:0f:e2:71:f9:0d:1a:9a:13:b7:d5:08:48:bd:50:58:b3:5e:20:63:86:29:ca:3e:cc:cc:78:26:e1:59:8f:5d:ca:8b:bc:49:31:6f:61:bd:42:ff:61:62:e1:22:35:24:26:9b:57:eb:e5:00:0d:ff:40:33:6c:46:c2:33:77:08:98:b2:7a:f6:43:f9:6d:48:df:bf:fe:fa:28:1e:7b:8a:cf:2d:61:ff:6c:87:98:a4:2c:62:9a:bb:10:8c:ff:34:48:70:66:b7:6d:72:c3:69:f9:39:4b:68:39:56:bd:a1:b3:6d:f4:77:f3:46:5b:5c:19:ac:4f:b3:74:6b:8c:c5:f1:89:cc:93:fe:0c:01:6f:88:17:dc:42:71:60:e3:ed:73:30:42:9c:a9:2f:3b:a2:78:8e:c8:6f:ba:d1:13:0c:d0:c7:5e:8c:10:fb:01:2e:37:9b:db:ac:f7:a1:ac:ba:7f:f8:92:e7:cb:41:44:c8:15:f9:f3:c4:bb:ad:51:5f:be:de:c7:ac:86:07:9f:40:ec:b9:0b:f6:b2:8b:cc:b5:55:33:66:ba:33:c2:c4:f0:a2:e9`,
	}
	domain := "example.com"
	certificates, _ := GetCert(domain)
	certificate := certificates[0]
	alg := ParseSigAlgorithm(certificate)

	if alg.Algorithm != want.Algorithm {
		t.Errorf("Algorithm field mismatch: got %s, want %s", alg.Algorithm, want.Algorithm)
	}

	if alg.Value != want.Value {
		t.Errorf("Value field mismatch: got %s, want %s", alg.Value, want.Value)
	}
}

func TestFingerprints(t *testing.T) {
	want := map[string]string{
		"sha256": "efba26d8c1ce3779ac77630a90f82163a3d6892ed6afee408672cf19eba7a362",
		"sha1":   "4da25a6d5ef62c5f95c7bd0a73ea3c177b36999d",
	}
	domain := "example.com"
	certificates, _ := GetCert(domain)
	certificate := certificates[0]
	sha256 := SHA256Fingerprint(certificate.Raw)
	sha1 := SHA1Fingerprint(certificate.Raw)

	if sha256 != want["sha256"] {
		t.Errorf("Value field mismatch: got %s, want %s", sha256, want["sha256"])
	}

	if sha1 != want["sha1"] {
		t.Errorf("Value field mismatch: got %s, want %s", sha1, want["sha1"])
	}
}

func TestParseIssuer(t *testing.T) {
	want := map[string]string{
		"CommonName":       "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
		"OrganizationName": "DigiCert Inc",
		"CountryName":      "US",
	}

	domain := "example.com"
	certificates, _ := GetCert(domain)
	certificate := certificates[0]

	issuer := ParseIssuer(certificate.Issuer)

	if issuer.CommonName != want["CommonName"] {
		t.Errorf("Value field mismatch: got %s, want %s", issuer.CommonName, want["CommonName"])
	}

	if issuer.OrganizationName != want["OrganizationName"] {
		t.Errorf("Value field mismatch: got %s, want %s", issuer.OrganizationName, want["OrganizationName"])
	}

	if issuer.CountryName != want["CountryName"] {
		t.Errorf("Value field mismatch: got %s, want %s", issuer.CountryName, want["CountryName"])
	}
}

func TestParseSerialNumber(t *testing.T) {
	want := "07:5b:ce:f3:06:89:c8:ad:df:13:e5:1a:f4:af:e1:87"

	domain := "example.com"
	certificates, _ := GetCert(domain)
	certificate := certificates[0]

	serialNumber := ParseSerialNumber(certificate)

	if serialNumber != want {
		t.Errorf("Value field mismatch: got %s, want %s", serialNumber, want)
	}

}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "example.com"},
		{"http://example.com", "example.com"},
		{"https://example.com/", "example.com"},
		{"http://example.com/", "example.com"},
		{"https://www.example.com", "www.example.com"},
		{"http://www.example.com", "www.example.com"},
		{"https://www.example.com/", "www.example.com"},
		{"http://www.example.com/", "www.example.com"},
		{"ftp://example.com", "example.com"},
		{"https://example.com/username/project-name", "example.com"},
	}

	for _, test := range tests {
		normalized := NormalizeURL(test.input)
		if normalized != test.expected {
			t.Errorf("NormalizeURL(%q) = %q; want %q", test.input, normalized, test.expected)
		}
	}
}
