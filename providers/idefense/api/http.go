package api

import (
	"io"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
)

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
		body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			resp.Body.Close()
			return nil, errors.Wrap(err, "cannot read http response")
		}
		resp.Body.Close()
		return nil, errors.Errorf("http error: %s %q", resp.Status, string(body))
	}

	return resp, nil
}
