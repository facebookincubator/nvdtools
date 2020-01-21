package client

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"sync/atomic"
)

var debug struct {
	// Print HTTP requests and responses to stderr.
	traceRequests bool

	requestNum uint64
}

func getBool(varName string) bool {
	v, _ := strconv.ParseBool(os.Getenv(varName))
	return v
}

func init() {
	debug.traceRequests = getBool("NVD_TRACE_REQUESTS")
}

func traceRequestStart(req *http.Request) uint64 {
	if !debug.traceRequests {
		return 0
	}
	id := atomic.AddUint64(&debug.requestNum, 1)
	data, _ := httputil.DumpRequest(req, false)
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
