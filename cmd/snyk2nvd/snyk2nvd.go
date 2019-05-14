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
	"io"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/pkg/errors"

	"github.com/facebookincubator/nvdtools/providers/snyk/api"
	"github.com/facebookincubator/nvdtools/providers/snyk/converter"
	"github.com/facebookincubator/nvdtools/providers/snyk/schema"
)

const (
	feedURL          = "https://snyk.io/partners/api/v4/vulndb/feed.json"
	defaultUserAgent = "snyk2nvd"
)

var (
	userAgent string
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	// set flags and parse
	var lf languageFilter
	flag.Var(&lf, "languages", "comma-separated list of languages to filter from input to output: golang, java, js, php, python; empty value means all")
	flag.StringVar(&userAgent, "user_agent", defaultUserAgent, "HTTP request User-Agent header")
	download := flag.Bool("download", false, "download feed from snyk.io, requires SNYK_TOKEN environment variable")
	dontConvert := flag.Bool("dont_convert", false, "if set, doesn't convert the feed to NVD json format")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: snyk2nvd [flags] [URI]")
		fmt.Fprintln(os.Stderr, "Reads snyk feed from standard input, FILE, or URL, and writes NVD CVE JSON to standard output.")
		fmt.Fprintln(os.Stderr, "Flags:")
		flag.PrintDefaults()
		os.Exit(1)
	}
	flag.Parse()

	// get feed
	r, err := obtainFeed(*download)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	if *dontConvert {
		io.Copy(os.Stdout, r)
		return
	}

	if err := convert(r, lf); err != nil {
		log.Fatalln(err)
	}
}

func obtainFeed(download bool) (io.ReadCloser, error) {
	if download {
		token := os.Getenv("SNYK_TOKEN")
		if token == "" {
			log.Fatal("Please set SNYK_TOKEN in environment")
		}
		parts := strings.SplitN(strings.TrimSuffix(token, "\n"), ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, errors.Errorf("malformed token: must contain 'consumer_id:secret'")
		}
		consumerID, secret := parts[0], parts[1]

		// determine User-Agent header, check if it's only ascii characters
		if !regexp.MustCompile("^[[:ascii:]]+$").MatchString(userAgent) {
			log.Println("User-Agent contains non ascii characters, using default")
			userAgent = defaultUserAgent
		}
		log.Printf("Downloading using http User-Agent: %s", userAgent)

		uri := flag.Arg(0)
		if uri == "" {
			uri = feedURL
		}

		client := api.NewClient(consumerID, secret, userAgent)
		return client.Get(uri)
	}

	// open the file if specified
	if len(flag.Args()) == 1 {
		return os.Open(flag.Arg(0))
	}

	// otherwise use stdin
	return os.Stdin, nil
}

func convert(r io.Reader, lf languageFilter) error {
	var snykFeed schema.Snyk
	if err := json.NewDecoder(r).Decode(&snykFeed); err != nil {
		return err
	}

	nvdFeed := converter.Convert(&snykFeed, lf)

	if err := json.NewEncoder(os.Stdout).Encode(nvdFeed); err != nil {
		return err
	}
	return nil
}

// language filter

type languageFilter map[string]bool

// String is a part of flag.Value interface implementation.
func (lf *languageFilter) String() string {
	languages := make([]string, 0, len(*lf))
	for language := range *lf {
		languages = append(languages, language)
	}
	return strings.Join(languages, ",")
}

// Set is a part of flag.Value interface implementation.
func (lf *languageFilter) Set(val string) error {
	if val == "" {
		return nil
	}
	if *lf == nil {
		*lf = make(languageFilter)
	}
	for _, v := range strings.Split(val, ",") {
		if v != "" {
			(*lf)[v] = true
		}
	}
	return nil
}
