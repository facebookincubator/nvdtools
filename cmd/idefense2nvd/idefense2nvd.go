package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/facebookincubator/nvdtools/providers/idefense/api"
	"github.com/facebookincubator/nvdtools/providers/idefense/converter"
	"github.com/facebookincubator/nvdtools/providers/idefense/schema"
)

const (
	baseURL      = "https://api.intelgraph.idefense.com"
	endpoint     = "rest/vulnerability/v0"
	startOfTimes = int64(1517472000) // 01 Feb 2018, 00:00:00 PST - we don't have access before this
)

var (
	parameters map[string]interface{}
	apiKey     string
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	apiKey = os.Getenv("IDEFENSE_TOKEN")
	if apiKey == "" {
		log.Fatal("Please set IDEFENSE_TOKEN in environment")
	}
}

func main() {
	url := flag.String("url", fmt.Sprintf("%s/%s", baseURL, endpoint), "iDefense API endpoint")
	parametersPath := flag.String("parameters_path", "", "Path to a json file which contains parameters used to query the API")
	sinceDuration := flag.String("since", "", "Golang duration string, use this instead of sinceUnix")
	sinceUnix := flag.Int64("since_unix", -1, "Unix timestamp since when should we download. If not set, downloads all available data")
	dontConvert := flag.Bool("dont_convert", false, "Should the feed be converted to NVD format or not")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	flag.Parse()

	since := *sinceUnix
	if *sinceDuration != "" {
		dur, err := time.ParseDuration("-" + *sinceDuration)
		if err != nil {
			log.Fatal(err)
		}
		since = time.Now().Add(dur).Unix()
	}
	if since < startOfTimes {
		since = startOfTimes
	}

	parameters = make(map[string]interface{})
	if *parametersPath != "" {
		if err := readParameters(*parametersPath); err != nil {
			log.Fatal(err)
		}
	}
	parameters["last_published.from"] = time.Unix(since, 0).Format("2006-01-02T15:04:05.000Z")

	// create the API
	client := api.NewClient(*url, apiKey, parameters)

	vulns, err := client.FetchAll()
	if err != nil {
		log.Fatal(err)
	}

	if *dontConvert {
		var output []*schema.IDefenseVulnerability
		for vuln := range vulns {
			output = append(output, vuln)
		}
		writeOutput(output)
	} else {
		writeOutput(converter.Convert(vulns))
	}
}

func writeOutput(output interface{}) {
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		log.Fatal(err)
	}
}

func readParameters(filepath string) error {
	f, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&parameters); err != nil {
		return err
	}
	return nil
}
