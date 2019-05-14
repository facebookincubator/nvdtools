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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/facebookincubator/nvdtools/providers/lib/client"
	"github.com/facebookincubator/nvdtools/providers/lib/runner"
	"github.com/facebookincubator/nvdtools/providers/redhat/schema"
)

const (
	perPage = 50
)

// Client struct
type Client struct {
	client.Client
	baseURL   string
	userAgent string
}

// NewClient creates an object which is used to query the iDefense API
func NewClient(baseURL, userAgent string) Client {
	c := client.Default()
	// 10 requests per second
	c = client.Throttle(c, time.Second, 10)
	// retry up to 5 times given statuses, 3 second delay between requests
	c = client.Retry(c, 5, 3*time.Second, http.StatusTooManyRequests, http.StatusGatewayTimeout)
	return Client{
		Client:    c,
		baseURL:   baseURL,
		userAgent: userAgent,
	}
}

// FetchAll will fetch all vulnerabilities
func (c *Client) FetchAllCVEs(since int64) (<-chan runner.Convertible, error) {
	output := make(chan runner.Convertible)
	wg := sync.WaitGroup{}

	for page := range c.fetchAllPages(since) {
		for _, cveItem := range *page {
			wg.Add(1)
			go func(cveid string) {
				defer wg.Done()
				log.Printf("\tfetching cve %s", cveid)
				cve, err := c.fetchCVE(cveid)
				if err != nil {
					log.Printf("error while fetching cve %s: %v", cveid, err)
					return
				}
				output <- cve
			}(cveItem.CVE)
		}
	}

	go func() {
		wg.Wait()
		close(output)
	}()

	return output, nil
}

func (c *Client) fetchCVE(cveid string) (*schema.CVE, error) {
	resp, err := c.queryPath(fmt.Sprintf("/cve/%s.json", cveid))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from feed: %v", err)
	}
	defer resp.Body.Close()

	var cve schema.CVE
	if err := json.NewDecoder(resp.Body).Decode(&cve); err != nil {
		return nil, fmt.Errorf("failed to decode cve response into a cve: %v", err)
	}

	return &cve, nil
}

func (c *Client) fetchAllPages(since int64) <-chan *schema.CVEList {
	output := make(chan *schema.CVEList)
	go func() {
		defer close(output)
		for page := 1; ; page++ {
			log.Printf("fetching page %d", page)
			if list, err := c.fetchListPage(since, page); err == nil {
				output <- list
				if len(*list) < perPage {
					break
				}
			} else {
				log.Printf("can't fecth page %d: %v", page, err)
				break
			}
		}
	}()
	return output
}

func (c *Client) fetchListPage(since int64, page int) (*schema.CVEList, error) {
	params := url.Values{}
	params.Add("per_page", strconv.Itoa(perPage))
	params.Add("page", strconv.Itoa(page))
	params.Add("after", time.Unix(since, 0).Format("2006-01-02")) // YYYY-MM-DD

	resp, err := c.queryPath("/cve.json?" + params.Encode())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch cve list: %v", err)
	}
	defer resp.Body.Close()

	var cveList schema.CVEList
	if err := json.NewDecoder(resp.Body).Decode(&cveList); err != nil {
		return nil, fmt.Errorf("failed to decode response into a list of cves: %v", err)
	}
	return &cveList, nil
}

func (c *Client) queryPath(path string) (*http.Response, error) {
	return client.Get(c.Client, c.baseURL+path, http.Header{"User-Agent": {c.userAgent}})
}
