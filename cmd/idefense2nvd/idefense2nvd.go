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

	"github.com/facebookincubator/nvdtools/providers/idefense/api"
	"github.com/facebookincubator/nvdtools/providers/idefense/schema"
	"github.com/facebookincubator/nvdtools/providers/lib/runner"
)

const (
	baseURL   = "https://api.intelgraph.idefense.com"
	userAgent = "idefense2nvd"
)

func Read(r io.Reader, c chan runner.Convertible) error {
	var vulns []*schema.IDefenseVulnerability
	if err := json.NewDecoder(r).Decode(&vulns); err != nil {
		return fmt.Errorf("can't decode into vulns: %v", err)
	}

	for _, vuln := range vulns {
		c <- vuln
	}

	return nil
}

func FetchSince(baseURL, userAgent string, since int64) (<-chan runner.Convertible, error) {
	apiKey := os.Getenv("IDEFENSE_TOKEN")
	if apiKey == "" {
		return nil, fmt.Errorf("Please set IDEFENSE_TOKEN in environment")
	}
	client := api.NewClient(baseURL, userAgent, apiKey)
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
