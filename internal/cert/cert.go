package cert

import (
	"fmt"
	"gocert/internal/utils"
	"gocert/models"
	"strings"
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
	}, nil
}

func ParseFromFile(path_to_file string) ([]models.CertificateMetadata, error) {
	var certificatesMetadata []models.CertificateMetadata

	splitPath := strings.Split(path_to_file, ".")
	fileExtension := splitPath[len(splitPath)-1]
	if fileExtension == "txt" {
		domains, err := utils.ReadTxtFile(path_to_file)
		if err != nil {
			return nil, err
		}

		for _, domain := range domains {
			certMetadata, err := Parse(domain)
			if err != nil {
				fmt.Printf("Can't get certificate for %s: %v\n", domain, err)
				continue
			}
			certificatesMetadata = append(certificatesMetadata, *certMetadata)
		}

		return certificatesMetadata, nil

	} else {
		fmt.Printf("%s not supported", fileExtension)
		return nil, nil
	}

}
