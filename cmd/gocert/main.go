package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"gocert/internal/cert"
	"gocert/internal/utils"
	"time"
)

func main() {

	domainPtr := flag.String("d", "", "Domain name")
	inputFilePtr := flag.String("f", "", "Input file")
	outputFilePtr := flag.String("o", "", "Output file")
	helpPtr := flag.Bool("h", false, "Help")

	flag.Parse()

	if *helpPtr {
		flag.Usage()
		return
	}

	if *domainPtr != "" && *inputFilePtr != "" {
		fmt.Println("You can't provide both domain and path")
		return
	}

	if *domainPtr == "" && *inputFilePtr == "" {
		fmt.Println("Please provide a domain or a file")
		return
	}

	if *inputFilePtr != "" && *outputFilePtr == "" {
		fmt.Println("Please provide output file -o 'output_file'")
		return
	}

	start := time.Now()

	if *domainPtr != "" {
		_, err := cert.Parse(*domainPtr)
		if err != nil {
			panic(err)
		}
	} else {

		certificatesMetadata, err := cert.ParseFromFile(*inputFilePtr)
		if err != nil {
			fmt.Printf("Can't read data from file: %v", err)
		}
		jsonData, _ := json.MarshalIndent(certificatesMetadata, "", "  ")
		err = utils.WriteToJSON(jsonData, *outputFilePtr)
		if err != nil {
			fmt.Printf("Can't write to json file: %v\n", err)
		}
	}

	elapsed := time.Since(start)
	fmt.Printf("Execution time: %s\n", elapsed)

}
