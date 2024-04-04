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
	filePtr := flag.String("f", "", "Path to file")
	helpPtr := flag.Bool("h", false, "Help")

	flag.Parse()

	if *helpPtr {
		flag.Usage()
		return
	}

	if *domainPtr != "" && *filePtr != "" {
		fmt.Println("You can't provide both domain and path")
		return
	}

	if *domainPtr == "" && *filePtr == "" {
		fmt.Println("Please provide a domain or a file:")
		fmt.Println("./gocert -d 'domain'")
		fmt.Println("./gocert -f 'file'")
		return
	}

	start := time.Now()

	if *domainPtr != "" {
		_, err := cert.Parse(*domainPtr)
		if err != nil {
			panic(err)
		}
	} else {
		certificatesMetadata, err := cert.ParseFromFile(*filePtr)
		if err != nil {
			fmt.Printf("Can't read data from file: %v", err)
		}
		jsonData, _ := json.MarshalIndent(certificatesMetadata, "", "  ")
		err = utils.WriteToJSON(jsonData, "test.json")
		if err != nil {
			fmt.Printf("Can't write to json file: %v\n", err)
		}
	}

	elapsed := time.Since(start)
	fmt.Printf("Execution time: %s\n", elapsed)

}
