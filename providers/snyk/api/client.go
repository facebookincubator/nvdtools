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
	"io"
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/facebookincubator/nvdtools/providers/lib/client"
	"github.com/facebookincubator/nvdtools/providers/snyk/schema"
)

type Client struct {
	client.Client
	baseURL    string
	consumerID string
	secret     string
}

func NewClient(c client.Client, baseURL, consumerID, secret string) *Client {
	return &Client{
		Client:     c,
		consumerID: consumerID,
		secret:     secret,
		baseURL:    baseURL,
	}
}

func (c *Client) FetchAllVulnerabilities(since int64) (<-chan *schema.Advisory, error) {
	// since is ignored, always download all from snyk
	content, err := c.get("vulnerabilities.json")
	if err != nil {
		return nil, fmt.Errorf("can't get vulnerabilities: %v", err)
	}

	output := make(chan *schema.Advisory)
	go func() {
		defer close(output)
		defer content.Close()
		var advisories schema.Advisories
		if err := json.NewDecoder(content).Decode(&advisories); err != nil {
			log.Printf("can't decode content into advisories: %v", err)
			return
		}
		for _, advs := range advisories {
			for _, adv := range advs {
				output <- adv
			}
		}
	}()

	return output, nil
}

func (c *Client) get(endpoint string) (io.ReadCloser, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.StandardClaims{
		Issuer:   c.consumerID,
		IssuedAt: time.Now().Unix(),
	})

	token, err := tok.SignedString([]byte(c.secret))
	if err != nil {
		return nil, fmt.Errorf("cannot create jwt token: %v", err)
	}

	url := fmt.Sprintf("%s/%s", c.baseURL, endpoint)
	resp, err := client.Get(c, url, http.Header{
		"Authorization": {"Bearer" + token},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilities at %q: %v", url, err)
	}

	return resp.Body, nil
}
