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
	var timeout int

	app := &cli.App{
		Name:      "teenydomains-gocert",
		Usage:     "Find SSL certificate information for a given domain",
		UsageText: "./gocert [global options]",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "domain",
				Aliases:     []string{"d"},
				Value:       "",
				Usage:       "Specify the domain to find SSL certificate information for",
				Destination: &domain,
			},
			&cli.StringFlag{
				Name:        "file",
				Aliases:     []string{"f"},
				Value:       "",
				Usage:       "Specify the file path containing a list of domains",
				Destination: &inputFile,
			},
			&cli.StringFlag{
				Name:        "output",
				Aliases:     []string{"o"},
				Value:       "",
				Usage:       "Optionally save data to a JSON file. If not provided, data will be printed to stdout",
				Destination: &outputFile,
			},
			&cli.IntFlag{
				Name:        "timeout",
				Aliases:     []string{"t"},
				Value:       3,
				Usage:       "Set the timeout in seconds for establishing connections. Set to 0 to disable timeouts.",
				Destination: &timeout,
			},
		},
		Action: func(cCtx *cli.Context) error {
			var err error
			var certData interface{}
			var jsonData []byte

			start := time.Now()

			if domain != "" {
				certData, err = cert.Parse(domain, timeout)
			} else if inputFile != "" {
				certData, err = cert.ParseFromFile(inputFile, timeout)
			} else {
				return fmt.Errorf("missing domain or input file")
			}

			if err != nil {
				return err
			}

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
