package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"gocert/internal/cert"
)

func main() {

	domainPtr := flag.String("d", "", "Domain name")

	flag.Parse()

	if *domainPtr == "" {
		fmt.Println("Please provide a domain:\ngo run main.go -d 'domain'")
		return
	}

	parsedCert, err := cert.Parse(*domainPtr)
	if err != nil {
		panic(err)
	}

	jsonData, _ := json.MarshalIndent(parsedCert, "", "  ")
	fmt.Println(string(jsonData))

}
