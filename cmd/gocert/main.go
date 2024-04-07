package main

import (
	"encoding/json"
	"fmt"
	"gocert/internal/cert"
	"gocert/internal/utils"
	"log"
	"os"
	"time"

	"github.com/urfave/cli/v2"
)

func main() {
	var domain string
	var inputFile string
	var outputFile string

	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "domain",
				Aliases:     []string{"d"},
				Value:       "",
				Usage:       "get certificate for given domain",
				Destination: &domain,
			},
			&cli.StringFlag{
				Name:        "file",
				Aliases:     []string{"f"},
				Value:       "",
				Usage:       "input file with domains",
				Destination: &inputFile,
			},
			&cli.StringFlag{
				Name:        "output",
				Aliases:     []string{"o"},
				Value:       "",
				Usage:       "specify the JSON file to which data will be saved",
				Destination: &outputFile,
			},
		},
		Action: func(cCtx *cli.Context) error {
			var err error
			var certData interface{}
			var jsonData []byte

			start := time.Now()

			if domain != "" {
				certData, err = cert.Parse(domain)
			} else if inputFile != "" {
				certData, err = cert.ParseFromFile(inputFile)
			} else {
				return fmt.Errorf("missing domain or input file")
			}

			if err != nil {
				return err
			}

			// Perform the JSON marshaling operation after getting the certificate data
			jsonData, err = json.MarshalIndent(certData, "", "  ")
			if err != nil {
				return err
			}

			if outputFile != "" {
				err = utils.WriteToJSON(jsonData, outputFile)
				if err != nil {
					fmt.Printf("Can't write to json file: %v\n", err)
					return err
				}
			} else {
				fmt.Println(string(jsonData))
			}

			elapsed := time.Since(start)
			fmt.Printf("Execution time: %s\n", elapsed)

			return nil
		},

		Before: func(cCtx *cli.Context) error {
			if domain == "" && inputFile == "" {
				fmt.Printf("\nError: at least a domain or an input file must be provided\n\n")
				cli.ShowAppHelpAndExit(cCtx, 1)
			}

			if domain != "" && inputFile != "" {
				fmt.Printf("\nError: you must provide either a domain or an input file\n\n")
				cli.ShowAppHelpAndExit(cCtx, 1)
			}
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
