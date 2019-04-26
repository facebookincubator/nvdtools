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
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
)

type httpError struct {
	code   int
	status string
	body   string
}

func (e httpError) Error() string {
	return fmt.Sprintf("http error: %s %q", e.status, e.body)
}

func (e httpError) isRateLimit() bool {
	return e.code == http.StatusTooManyRequests
}

// Query will query the given URL and then return the response if response status is HTTP.OK
func queryURL(u string, header http.Header) (*http.Response, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create http get request")
	}
	req.Header = header

	// execute the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get url")
	}

	// check response
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			return nil, errors.Wrap(err, "cannot read http response")
		}
		return nil, httpError{resp.StatusCode, resp.Status, string(body)}
	}

	return resp, nil
}
