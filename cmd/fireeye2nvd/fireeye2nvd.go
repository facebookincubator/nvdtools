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
	"regexp"
	"time"

	"github.com/facebookincubator/nvdtools/providers/fireeye/api"
	"github.com/facebookincubator/nvdtools/providers/fireeye/converter"
)

const (
	baseURL          = "https://api.isightpartners.com"
	defaultUserAgent = "fireeye2nvd"
)

var (
	publicKey  string
	privateKey string
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	publicKey = os.Getenv("FIREEYE_PUBLIC")
	if publicKey == "" {
		log.Fatalln("Please set FIREEYE_PUBLIC in environment")
	}
	privateKey = os.Getenv("FIREEYE_PRIVATE")
	if privateKey == "" {
		log.Fatalln("Please set FIREEYE_PRIVATE in environment")
	}
}

func main() {
	baseURL := flag.String("base_url", baseURL, "API base URL")
	userAgent := flag.String("user_agent", defaultUserAgent, "User agent to be used when sending requests")
	sinceUnix := flag.Int64("since_unix", 0, "Unix timestamp since when should we download. If not set, downloads all available data")
	sinceDuration := flag.String("since", "", "Golang duration string, overrides -since_unix flag")
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
			log.Fatalln(err)
		}
		since = time.Now().Add(dur).Unix()
	}

	if !regexp.MustCompile("^[[:ascii:]]+$").MatchString(*userAgent) {
		log.Println("User-Agent contains non ascii characters, using default")
		*userAgent = defaultUserAgent
	}

	// create the API
	client, err := api.NewClient(*baseURL, *userAgent, publicKey, privateKey)
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("Downloading since %s\n", time.Unix(since, 0).Format(time.RFC1123))
	vulns, err := client.FetchAllVulnerabilitiesSince(since)
	if err != nil {
		log.Fatalln(err)
	}

	if *dontConvert {
		writeOutput(vulns)
	} else {
		writeOutput(converter.Convert(vulns))
	}
}

func writeOutput(output interface{}) {
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		log.Fatalln(err)
	}
}
