package client

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"sync/atomic"
)

var debug struct {
	// Print HTTP requests and responses to stderr.
	traceRequests bool
	// When tools issue concurrent GET requests, the normal behaviour is to
	// cancel pending requests as soon as one request fails. This option
	// restores the old behaviour or executing the remaning requests anyway.
	continueDownloading bool

	requestNum uint64
}

func getBool(varName string) bool {
	v, _ := strconv.ParseBool(os.Getenv(varName))
	return v
}

func init() {
	debug.traceRequests = getBool("NVD_TRACE_REQUESTS")
	debug.continueDownloading = getBool("NVD_CONTINUE_DOWNLOADING")
}

func obfuscateHeaders(req *http.Request) *http.Request {
	authHeaders := []string{
		"Authorization",
		// fireeye
		"X-Auth",
		"X-Auth-Hash",
		// idefense
		"Auth-Token",
	}

	headers := req.Header.Clone()
	for _, header := range authHeaders {
		if headers.Get(header) == "" {
			continue
		}
		headers.Set(header, "<obfuscated>")
	}

	// A shallow copy is enough for this usage.
	newReq := *req
	newReq.Header = headers
	return &newReq
}

func traceRequestStart(req *http.Request) uint64 {
	if !debug.traceRequests {
		return 0
	}
	id := atomic.AddUint64(&debug.requestNum, 1)
	data, _ := httputil.DumpRequest(obfuscateHeaders(req), false)
	fmt.Fprintf(os.Stderr, "Req %d: %s", id, string(data))
	return id
}

func traceRequestEnd(id uint64, resp *http.Response) {
	if !debug.traceRequests {
		return
	}
	if resp == nil {
		return
	}
	data, _ := httputil.DumpResponse(resp, false)
	fmt.Fprintf(os.Stderr, "Req %d: %s", id, string(data))
}

// StopOrContinue can help controlling the behaviour of concurrent GET requests
// when using an errgroup and encountering an error. Depending on the
// NVD_CONTINUE_DOWNLOADING env variable, this function will return the passed
// error (when we want to stop pending requests) or just log the error (when we
// want the pending requests to continue being processed).
func StopOrContinue(err error) error {
	if debug.continueDownloading {
		log.Println(err)
		return nil
	}
	return err
}
