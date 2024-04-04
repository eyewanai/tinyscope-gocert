package main

import (
	"fmt"
	"gocert/internal/cert"
)

func main() {
	domain := "https://vtb.ru/"

	certs, err := cert.GetCert(domain)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(certs))

	certificate := certs[0]
	sha1 := cert.SHA1Fingerprint(certificate.Raw)
	sha256 := cert.SHA256Fingerprint(certificate.Raw)
	fmt.Println("sha1", sha1)
	fmt.Println("sha256", sha256)
	fmt.Println(certificate.Issuer)
	issuer := cert.ParseIssuer(certificate.Issuer)
	fmt.Printf("%#v\n", issuer)

	fingerprints := cert.ParseFingerprints(certificate.Raw)
	fmt.Printf("%#v\n", fingerprints)

	fmt.Println(certificate.DNSNames)

	san := cert.ParseSAN(certificate)
	fmt.Printf("%#v\n", san)

	// jsonData, _ := json.MarshalIndent(san, "", "    ")
	// fmt.Println(string(jsonData))
	fmt.Printf("%#v\n", cert.ParseSigAlgorithm(certificate))
}
