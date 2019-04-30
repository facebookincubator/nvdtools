// Copyright (c) Facebook, Inc. and its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	baseURL  = "https://api.intelgraph.idefense.com"
	endpoint = "rest/vulnerability/v0"
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
	sinceDuration := flag.String("since", "", "Golang duration string, overrides -since_unix flag")
	sinceUnix := flag.Int64("since_unix", 0, "Unix timestamp since when should we download. If not set, downloads all available data")
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
