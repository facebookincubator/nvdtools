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

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/facebookincubator/nvdtools/providers/lib/download"
	"github.com/facebookincubator/nvdtools/providers/lib/runner"
	"github.com/facebookincubator/nvdtools/providers/rbs/schema"
)

const (
	pageSize = 100
)

type Client struct {
	client    *http.Client
	baseURL   string
	userAgent string
}

func NewClient(clientID, clientSecret, tokenURL, baseURL, userAgent string) (*Client, error) {
	httpClient, err := download.Client()
	if err != nil {
		return nil, fmt.Errorf("couldn't obtain http client: %v", err)
	}

	ctx := context.WithValue(oauth2.NoContext, oauth2.HTTPClient, httpClient)

	conf := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
	}

	c := Client{
		client:    conf.Client(ctx),
		baseURL:   baseURL,
		userAgent: userAgent,
	}

	return &c, nil
}

func (c *Client) FetchAllVulnerabilitiesAfterVulndbID(vulndbID int) (<-chan runner.Convertible, error) {
	u := fmt.Sprintf("%d/find_next_to_vulndb_id_full", vulndbID)

	return c.fetchAllVulnerabilities(func() string { return u })
}

func (c *Client) FetchAllVulnerabilities(since int64) (<-chan runner.Convertible, error) {
	from := time.Unix(since, 0)
	getEndpoint := func() string {
		// we need to recalculate hours ago on each request, if the fetching takes more than an hour
		duration := time.Now().Sub(from)
		u := fmt.Sprintf("find_by_time_full?hours_ago=%d", int(duration.Hours()))
		return u
	}
	return c.fetchAllVulnerabilities(getEndpoint)
}

func (c *Client) fetchAllVulnerabilities(getEndpoint func() string) (<-chan runner.Convertible, error) {

	fetch := func(page, size int) (*schema.VulnerabilityResult, error) {
		u, err := url.Parse(fmt.Sprintf("%s/api/v1/vulnerabilities/%s", c.baseURL, getEndpoint()))
		if err != nil {
			return nil, fmt.Errorf("can't parse url: %v", err)
		}
		values := u.Query()
		values.Set("page", fmt.Sprintf("%d", page))
		values.Set("size", fmt.Sprintf("%d", size))
		u.RawQuery = values.Encode()
		return c.getResult(u.String())
	}

	result, err := fetch(1, 1)
	if err != nil {
		return nil, err
	}

	totalVulns := result.TotalEntries
	if totalVulns == 0 {
		return nil, fmt.Errorf("no vulnerabilities found")
	}

	output := make(chan runner.Convertible)
	numPages := (totalVulns-1)/pageSize + 1

	// fetch pages concurrently
	log.Printf("starting sync for %d vulnerabilities over %d pages\n", totalVulns, numPages)
	wg := sync.WaitGroup{}
	for page := 1; page <= numPages; page++ {
		page := page
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := fetch(page, pageSize)
			if err != nil {
				log.Printf("failed to get page %d: %v", page, err)
				return
			}
			for _, vuln := range result.Vulnerabilities {
				if vuln != nil {
					output <- vuln
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(output)
	}()

	return output, nil
}

func (c *Client) getResult(u string) (*schema.VulnerabilityResult, error) {
	resp, err := c.get(u)
	if err != nil {
		return nil, fmt.Errorf("can't get response: %v", err)
	}
	defer resp.Body.Close()

	var result schema.VulnerabilityResult
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("can't decode result: %v", err)
	}

	return &result, nil
}

func (c *Client) get(u string) (*http.Response, error) {
	header := http.Header{}
	header.Set("User-Agent", c.userAgent)
	return download.GetWithClient(c.client, u, header)
}
