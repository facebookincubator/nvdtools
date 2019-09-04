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

package client

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

// FailedRetries is an error returned when all retries have been exhausted
type FailedRetries int

// Error is a part of the error interface
func (fr FailedRetries) Error() string {
	return fmt.Sprintf("failed to fetch after %d retries", int(fr))
}

// Retry will retry all given requests for the specified number of times
//	- if status is 200, returns
//	- if status is one of the specified and hasn't been retried the total number of times, retry
//	- otherwise, fail the request
func Retry(c Client, retries int, delay time.Duration, statuses ...int) Client {
	if retries <= 0 || len(statuses) == 0 {
		// if no retries, return the normal client
		// if no statuses are retried, do the same
		return c
	}
	retriable := make(map[int]bool, len(statuses))
	for _, status := range statuses {
		retriable[status] = true
	}
	return &executorClient{c, &retryExecutor{retries, delay, retriable}}
}

type retryExecutor struct {
	retries   int
	delay     time.Duration
	retriable map[int]bool
}

func (c *retryExecutor) execute(f func() (*http.Response, error)) (*http.Response, error) {
	for retry := 0; retry <= c.retries; retry++ {
		resp, err := f()
		if err != nil {
			return resp, err
		}

		switch {
		default:
			// unknown status, read the error and return it
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			if err != nil {
				return nil, fmt.Errorf("cannot read http response: %v", err)
			}
			return nil, &Err{resp.StatusCode, resp.Status, string(body)}
		case resp.StatusCode == http.StatusOK:
			return resp, nil
		case c.retriable[resp.StatusCode]:
			// get out of switch, sleep and retry
		}

		if retry != c.retries {
			time.Sleep(c.delay)
		}
	}
	// no more retries left
	return nil, FailedRetries(c.retries)
}
