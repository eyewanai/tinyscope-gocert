package cert

import (
	"fmt"
	"gocert/internal/utils"
	"gocert/models"
	"strings"

	"github.com/cheggaaa/pb/v3"
)

func Parse(domain string) (*models.CertificateMetadata, error) {
	domain = NormalizeURL(domain)
	certificates, err := GetCert(domain)
	if err != nil {
		return nil, err
	}

	certificate := certificates[0]

	return &models.CertificateMetadata{
		DomainName:              domain,
		CertificateFingerprints: ParseFingerprints(certificate.Raw),
		SignatureAlgorithm:      ParseSigAlgorithm(certificate),
		SubjectAlternativeNames: ParseSAN(certificate),
		Issuer:                  ParseIssuer(certificate.Issuer),
	}, nil
}

func ParseFromFile(filePath string) ([]models.CertificateMetadata, error) {
	var certificatesMetadata []models.CertificateMetadata

	splitPath := strings.Split(filePath, ".")
	fileExtension := splitPath[len(splitPath)-1]
	if fileExtension == "txt" {
		domains, err := utils.ReadTxtFile(filePath)
		if err != nil {
			return nil, err
		}

		count := len(domains)
		bar := pb.StartNew(count)

		for _, domain := range domains {
			certMetadata, err := Parse(domain)
			if err != nil {
				fmt.Printf("Can't get certificate for %s: %v\n", domain, err)
				bar.Increment()
				continue
			}
			certificatesMetadata = append(certificatesMetadata, *certMetadata)
			bar.Increment()
		}

		bar.Finish()

		return certificatesMetadata, nil

	} else {
		fmt.Printf("%s not supported", fileExtension)
		return nil, nil
	}

}
