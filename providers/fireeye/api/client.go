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
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/facebookincubator/nvdtools/providers/fireeye/schema"
	"github.com/facebookincubator/nvdtools/providers/lib/download"
	"github.com/pkg/errors"
)

const (
	acceptVersion = "2.6"
)

// Client struct
type Client struct {
	hash      hash.Hash
	publicKey string
	baseURL   string
	userAgent string
	m         sync.Mutex
}

// NewClient creates an object which is used to query the iDefense API
func NewClient(baseURL, userAgent, publicKey, privateKey string) (*Client, error) {
	if !regexp.MustCompile("^[[:ascii:]]+$").MatchString(userAgent) {
		return nil, fmt.Errorf("user agent contains non ascii characters")
	}
	return &Client{
		hash:      hmac.New(sha256.New, []byte(privateKey)),
		publicKey: publicKey,
		baseURL:   baseURL,
		userAgent: userAgent,
	}, nil
}

// Request will fetch the given endpoint and return the response
func (c *Client) Request(endpoint string) (io.Reader, error) {
	req, err := http.NewRequest("GET", c.baseURL+endpoint, nil)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create http get request")
	}

	acceptHeader := "application/json"
	timestamp := time.Now().Format(time.RFC1123)
	auth := c.getHash("%s%s%s%s", endpoint, acceptVersion, acceptHeader, timestamp)

	// FireEye required
	req.Header.Set("Accept", acceptHeader)
	req.Header.Set("Accept-Version", acceptVersion)
	req.Header.Set("X-Auth", c.publicKey)
	req.Header.Set("X-Auth-Hash", auth)
	req.Header.Set("Date", timestamp)

	req.Header.Set("User-Agent", c.userAgent)

	// execute the request
	client, err := download.Client()
	if err != nil {
		return nil, errors.Wrap(err, "can't obtain http client")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get url")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%d - %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	// Fireeye response is always {success:boolean, message:something}
	// First we decode this from response, and fail fast if success = false
	// Otherwise, we return the message only

	var fireeyeResult schema.FireeyeResult
	body := io.LimitReader(resp.Body, 2<<30) // 1 GB
	if err := json.NewDecoder(body).Decode(&fireeyeResult); err != nil {
		return nil, errors.Wrap(err, "couldn't decode result")
	}

	var buff bytes.Buffer
	if err := json.NewEncoder(&buff).Encode(fireeyeResult.Message); err != nil {
		return nil, errors.Wrap(err, "couldn't encode message back to buffer")
	}

	if !fireeyeResult.Success {
		var errorMessage schema.FireeyeResultErrorMessage
		if err := json.Unmarshal(buff.Bytes(), &errorMessage); err != nil {
			return nil, errors.Wrap(err, "failed to decode error message")
		}
		return nil, fmt.Errorf("%s: %s", errorMessage.Error, errorMessage.Description)
	}

	return &buff, nil
}

func (c *Client) getHash(format string, a ...interface{}) string {
	c.m.Lock()
	defer c.m.Unlock()
	fmt.Fprintf(c.hash, format, a...)
	b := c.hash.Sum(nil)
	c.hash.Reset()
	return hex.EncodeToString(b)
}
