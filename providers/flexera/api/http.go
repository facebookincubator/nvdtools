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
