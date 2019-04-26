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

	"github.com/facebookincubator/nvdtools/providers/flexera/api"
	"github.com/facebookincubator/nvdtools/providers/flexera/converter"
	"github.com/facebookincubator/nvdtools/providers/flexera/schema"
)

const (
	baseURL      = "https://api.app.secunia.com"
	startOfTimes = int64(1517472000) // 01 Feb 2018, 00:00:00 PST
)

var (
	apiKey string
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	apiKey = os.Getenv("FLEXERA_TOKEN")
	if apiKey == "" {
		log.Fatal("Please set FLEXERA_TOKEN in environment")
	}
}

func main() {
	baseURL := flag.String("url", baseURL, "Flexera API base URL")
	sinceDuration := flag.String("since", "", "Golang duration string, use this instead of sinceUnix")
	sinceUnix := flag.Int64("since_unix", -1, "Unix timestamp since when should we download. If not set, downloads all available data")
	only := flag.String("only", "", "If present, it will only download this advisory")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	flag.Parse()

	// create the API
	client := api.NewClient(*baseURL, apiKey)
	var fetch func() (<-chan *schema.FlexeraAdvisory, error)

	if *only != "" {
		fetch = func() (<-chan *schema.FlexeraAdvisory, error) {
			log.Printf("Downloading only: %s\n", *only)
			adv, err := client.Fetch(*only)
			if err != nil {
				return nil, err
			}
			output := make(chan *schema.FlexeraAdvisory, 1)
			output <- adv
			close(output)
			return output, nil
		}
	} else {
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

		from, to := since, time.Now().Unix()

		fetch = func() (<-chan *schema.FlexeraAdvisory, error) {
			log.Printf(
				"Download window: %s - %s\n",
				time.Unix(from, 0).Format(time.RFC1123),
				time.Unix(to, 0).Format(time.RFC1123),
			)
			return client.FetchAll(from, to)
		}
	}

	advCh, err := fetch()
	if err != nil {
		log.Fatal(err)
	}

	converted := converter.Convert(advCh)
	if err := json.NewEncoder(os.Stdout).Encode(converted); err != nil {
		log.Fatal(err)
	}
}
