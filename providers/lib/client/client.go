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
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	// TODO lose download package, move all to here
	"github.com/facebookincubator/nvdtools/providers/lib/download"
	"github.com/facebookincubator/nvdtools/providers/lib/rate"
)

// Config is used to configure a client
type Config struct {
	numRetries        int
	retryDelay        time.Duration
	retriable         ints
	requestsPerPeriod int
	period            time.Duration
}

// AddFlags adds flags used to configure a client
func (conf *Config) AddFlags() {
	flag.IntVar(&conf.numRetries, "num-retries", 0, "how many times will specified statuses get retried. 0 means no retries")
	// TODO implement exponential backoff (for some statuses?)
	flag.DurationVar(&conf.retryDelay, "retry-delay", time.Second, "delay between each retry")
	flag.Var(&conf.retriable, "retry", "which http statuses to retry. specify multiple by specifying the flag multiple times or using a comma")
	flag.IntVar(&conf.requestsPerPeriod, "requests-per-period", 0, "how many requests per period to make. 0 means no throttling")
	flag.DurationVar(&conf.period, "period", time.Second, "period in which requests are capped by the requests-per-period flag")
}

// Configure configures the given client (add throttling, retries, ...)
func (conf *Config) Configure(c Client) Client {
	if conf.numRetries > 0 {
		c = Retry(c, conf.numRetries, conf.retryDelay, conf.retriable...)
	}
	if conf.requestsPerPeriod > 0 {
		c = Throttle(c, conf.period, conf.requestsPerPeriod)
	}
	return c
}

// Err encapsulates stuff from the http.Response
type Err struct {
	Code   int
	Status string
	Body   string
}

// Error is a part of the error interface
func (e *Err) Error() string {
	return fmt.Sprintf("http error %s:\n %q", e.Status, e.Body)
}

// Client is an interface used for making http requests
type Client interface {
	Do(req *http.Request) (*http.Response, error)
	Get(url string) (*http.Response, error)
}

// Get will create a GET request with given headers and call Do on the client
func Get(c Client, url string, header http.Header) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http get request: %v", err)
	}
	req.Header = header

	return c.Do(req)
}

// Default returns the default http client to use
func Default() Client {
	// TODO merge into one function
	if cl, err := download.Client(); err == nil {
		return cl
	}
	return http.DefaultClient
}

// Throttle creates a rate limitted client - all requests are throttled
func Throttle(c Client, period time.Duration, requestsPerPeriod int) Client {
	limiter := rate.BurstyLimiter(period, requestsPerPeriod)
	return &rateLimitedClient{c, limiter}
}

type rateLimitedClient struct {
	Client
	rate.Limiter
}

func (c *rateLimitedClient) Do(req *http.Request) (*http.Response, error) {
	c.Limiter.Allow() // block until we can make another request
	return c.Client.Do(req)
}

func (c *rateLimitedClient) Get(url string) (*http.Response, error) {
	c.Limiter.Allow() // block until we can make another request
	return c.Client.Get(url)
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
	return &retriableClient{c, retries, delay, retriable}
}

// FailedRetries is an error returned when all retries have been exhausted
type FailedRetries int

func (fr FailedRetries) Error() string {
	return fmt.Sprintf("failed to fetch after %d retries", int(fr))
}

type retriableClient struct {
	Client
	retries   int
	delay     time.Duration
	retriable map[int]bool
}

func (c *retriableClient) Do(req *http.Request) (*http.Response, error) {
	for retry := 0; retry <= c.retries; retry++ {
		resp, err := c.Client.Do(req)
		if err != nil {
			return resp, err
		}

		if resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		if err = c.checkStatus(resp); err != nil {
			return nil, err
		}

		if retry != c.retries {
			time.Sleep(c.delay)
		}
	}
	// no more retries left
	return nil, FailedRetries(c.retries)
}

func (c *retriableClient) Get(url string) (*http.Response, error) {
	for retry := 0; retry <= c.retries; retry++ {
		resp, err := c.Client.Get(url)
		if err != nil {
			return resp, err
		}

		if resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		if err = c.checkStatus(resp); err != nil {
			return nil, err
		}

		if retry != c.retries {
			time.Sleep(c.delay)
		}
	}
	// no more retries left
	return nil, FailedRetries(c.retries)
}

// returns an error if status is not retriable
func (c *retriableClient) checkStatus(resp *http.Response) error {
	if !c.retriable[resp.StatusCode] {
		// unknown status, read the error and return it
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			return fmt.Errorf("cannot read http response: %v", err)
		}
		return &Err{resp.StatusCode, resp.Status, string(body)}
	}
	return nil
}

// flag vars

type ints []int

// Set is a part of the flag.Value interface
func (ii *ints) Set(ss string) error {
	if ii == nil {
		ii = new(ints)
	}
	parts := strings.Split(ss, ",")
	if *ii == nil {
		*ii = make(ints, 0, len(parts))
	}

	for _, s := range parts {
		i, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		*ii = append(*ii, i)
	}
	return nil
}

func (ii *ints) String() string {
	if ii == nil || *ii == nil {
		return ""
	}
	var sb strings.Builder
	for idx, i := range *ii {
		if idx > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(i))
	}
	return sb.String()
}
