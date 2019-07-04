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
	"fmt"
	"io"
	"log"
	"os"

	"github.com/facebookincubator/nvdtools/providers/fireeye/api"
	"github.com/facebookincubator/nvdtools/providers/fireeye/schema"
	"github.com/facebookincubator/nvdtools/providers/lib/runner"
)

const (
	baseURL   = "https://api.isightpartners.com"
	userAgent = "fireeye2nvd"
)

func Read(r io.Reader, c chan runner.Convertible) error {
	var vulns map[string]*schema.Vulnerability
	if err := json.NewDecoder(r).Decode(&vulns); err != nil {
		return fmt.Errorf("can't decode into vulns: %v", err)
	}

	for _, vuln := range vulns {
		c <- vuln
	}

	return nil
}

func FetchSince(baseURL, userAgent string, since int64) (<-chan runner.Convertible, error) {
	publicKey := os.Getenv("FIREEYE_PUBLIC")
	if publicKey == "" {
		return nil, fmt.Errorf("Please set FIREEYE_PUBLIC in environment")
	}
	privateKey := os.Getenv("FIREEYE_PRIVATE")
	if privateKey == "" {
		return nil, fmt.Errorf("Please set FIREEYE_PRIVATE in environment")
	}

	client, err := api.NewClient(baseURL, userAgent, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("can't create client")
	}

	return client.FetchAllVulnerabilities(since)
}

func main() {
	r := runner.Runner{
		Config: runner.Config{
			BaseURL:   baseURL,
			UserAgent: userAgent,
		},
		FetchSince: FetchSince,
		Read:       Read,
	}

	if err := r.Run(); err != nil {
		log.Println(err)
	}
}
