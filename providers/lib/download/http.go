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

package download

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

// Client will return a client to be used when making http requests
// Returns an error if it can't be acquired
func Client() (*http.Client, error) {
	return http.DefaultClient, nil
}

// Err encapsulates stuff from the http.Response
type Err struct {
	Code   int
	Status string
	Body   string
}

func (e Err) Error() string {
	return fmt.Sprintf("http error %s:\n %q", e.Status, e.Body)
}

// Get will call GetWithClient using the default client
func Get(url string, header http.Header) (*http.Response, error) {
	client, err := Client()
	if err != nil {
		return nil, fmt.Errorf("can't obtain default client: %v", err)
	}
	return GetWithClient(client, url, header)
}

// GetWithClient will query the given URL and then return the response if response status is HTTP.OK
// if status is not HTTP.OK, returns Err
func GetWithClient(client *http.Client, url string, header http.Header) (*http.Response, error) {
	// create the request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http get request: %v", err)
	}
	req.Header = header

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot get url: %v", err)
	}

	// check response
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			return nil, fmt.Errorf("cannot read http response: %v", err)
		}
		return nil, Err{resp.StatusCode, resp.Status, string(body)}
	}

	return resp, nil
}
