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

package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/golang/glog"
)

type config struct {
	nProcessors               int
	cpesAt, cvesAt, matchesAt int
	feedFormat                string
	inFieldSep, inRecSep      string
	outFieldSep, outRecSep    string
	cpuProfile, memProfile    string
	skip                      fieldsToSkip
	indexedDict               bool
	requireVersion            bool
	cacheSize                 int
	overrides                 multiString
}

func (c *config) addFlags() {
	flag.IntVar(&c.nProcessors, "nproc", 1, "number of concurrent goroutines that perform CVE lookup")
	flag.IntVar(&c.cpesAt, "cpe", 0, "look for CPE names in input at this position (starts with 1)")
	flag.IntVar(&c.cvesAt, "cve", 0, "output CVEs at this position (starts with 1)")
	flag.IntVar(&c.matchesAt, "matches", 0, "output CPEs that matches CVE at this position; 0 disables the output")
	flag.IntVar(&c.cacheSize, "cache_size", 0, "limit the cache size to this amount in bytes; 0 removes the limit, -1 disables caching")
	flag.StringVar(&c.feedFormat, "feed", "xml", "vulnerability feed format (currently xml and json values are supported")
	flag.StringVar(&c.inFieldSep, "d", "\t", "input columns delimiter")
	flag.StringVar(&c.inRecSep, "d2", ",", "inner input columns delimiter: separates elements of list passed into a CSV columns")
	flag.StringVar(&c.outFieldSep, "o", "\t", "output columns delimiter")
	flag.StringVar(&c.outRecSep, "o2", ",", "inner output columns delimiter: separates elements of lists in output CSV columns")
	flag.StringVar(&c.cpuProfile, "cpuprofile", "", "file to store CPU profile data to; empty value disables CPU profiling")
	flag.StringVar(&c.memProfile, "memprofile", "", "file to store memory profile data to; empty value disables memory profiling")
	flag.Var(&c.skip, "e", "comma separated list of fields to erase from output; starts at 1, supports ranges (e.g. 1-3); processed before the vulnerablitie field added")
	flag.BoolVar(&c.indexedDict, "idxd", false, "build and use an index for CVE dictionary: increases the processing speed, but might miss some matches")
	flag.BoolVar(&c.requireVersion, "require_version", false, "ignore matches of CPEs with version ANY")
	flag.Var(&c.overrides, "r", "overRide: path to override feed, can be specified multiple times")
}

func (c *config) mustBeValid() {
	if flag.NArg() < 1 {
		glog.Error("feed file wasn't provided")
		flag.Usage()
	}
	if c.cpesAt <= 0 {
		glog.Error("-cpe flag wasn't provided")
		flag.Usage()
	}
	if c.cvesAt <= 0 {
		glog.Error("-cve flag wasn't provided")
		flag.Usage()
	}
	if c.matchesAt < 0 {
		glog.Errorf("-matches value is invalid %d", c.matchesAt)
		flag.Usage()
	}
}

func process(in <-chan []string, out chan<- []string, cache *cvefeed.Cache, cfg config, nlines *uint64) {
	cpesAt := cfg.cpesAt - 1
	for rec := range in {
		if cpesAt >= len(rec) {
			glog.Errorf("not enough fields in input (%d)", len(rec))
			continue
		}
		cpeList := strings.Split(rec[cpesAt], cfg.inRecSep)
		cpes := make([]*wfn.Attributes, len(cpeList))
		for i, uri := range cpeList {
			attr, err := wfn.UnbindURI(uri)
			if err != nil {
				glog.Errorf("couldn't unbind uri %q: %v", uri, err)
				continue
			}
			cpes[i] = attr
		}
		rec[cpesAt] = strings.Join(cpeList, cfg.outRecSep)
		for _, matches := range cache.Get(cpes) {
			matchingCPEs := make([]string, len(matches.CPEs))
			for i, attr := range matches.CPEs {
				if attr == nil {
					glog.Errorf("%s matches nil CPE", matches.CVE)
					continue
				}
				matchingCPEs[i] = (*wfn.Attributes)(attr).BindToURI()
			}
			rec2 := make([]string, len(rec))
			copy(rec2, rec)
			if cfg.matchesAt != 0 {
				rec2 = cfg.skip.appendAt(rec2, cfg.cvesAt-1, matches.CVE, cfg.matchesAt-1, strings.Join(matchingCPEs, cfg.outRecSep))
			} else {
				rec2 = cfg.skip.appendAt(rec2, cfg.cvesAt-1, matches.CVE)
			}
			out <- rec2
		}
		n := atomic.AddUint64(nlines, 1)
		if n > 0 {
			if n%10000 == 0 {
				glog.V(1).Infoln(n, "lines processed")
			} else if n%1000 == 0 {
				glog.V(2).Infoln(n, "lines processed")
			} else if n%100 == 0 {
				glog.V(3).Infoln(n, "lines processed")
			}
		}
	}
}

func processInput(in io.Reader, out io.Writer, cache *cvefeed.Cache, cfg config) chan struct{} {
	done := make(chan struct{})
	procIn := make(chan []string)
	procOut := make(chan []string)

	r := csv.NewReader(in)
	r.Comma = rune(cfg.inFieldSep[0])

	w := csv.NewWriter(out)
	w.Comma = rune(cfg.outFieldSep[0])

	// spawn processing goroutines
	var linesProcessed uint64
	var procWG sync.WaitGroup
	procWG.Add(cfg.nProcessors)
	for i := 0; i < cfg.nProcessors; i++ {
		go func() {
			process(procIn, procOut, cache, cfg, &linesProcessed)
			procWG.Done()
		}()
	}

	// write processed results in background
	go func() {
		for rec := range procOut {
			if err := w.Write(rec); err != nil {
				glog.Errorf("write error: %v", err)
			}
			w.Flush()
		}
		if err := w.Error(); err != nil {
			glog.Errorf("write error: %v", err)
		}
		close(done)
	}()

	start := time.Now()
	// main goroutine reads input and sends it to processors
	for line := 1; ; line++ {
		rec, err := r.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			glog.Errorf("read error at line %d: %v", line, err)
		}
		procIn <- rec
	}

	close(procIn)
	procWG.Wait()
	close(procOut)
	glog.V(1).Infof("processed %d lines in %v", linesProcessed, time.Since(start))
	return done
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] nvd_feed.xml.gz...\n", path.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "flags:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	flag.Set("logtostderr", "true")
}

func main() {
	var cfg config
	cfg.addFlags()
	flag.Parse()
	cfg.mustBeValid()

	glog.V(1).Info("loading NVD feeds...")
	start := time.Now()
	var dict, overrides cvefeed.Dictionary
	var err error
	switch cfg.feedFormat {
	case "xml":
		if dict, err = cvefeed.LoadXMLDictionary(flag.Args()...); err == nil {
			overrides, err = cvefeed.LoadXMLDictionary(cfg.overrides...)
		}
	case "json":
		if dict, err = cvefeed.LoadJSONDictionary(flag.Args()...); err == nil {
			overrides, err = cvefeed.LoadJSONDictionary(cfg.overrides...)
		}
	default:
		glog.Fatalf("unknown vulnerability feed format %q", cfg.feedFormat)
	}
	if err != nil {
		glog.Error(err)
		if len(dict) == 0 {
			glog.Error("dictionary is empty")
			os.Exit(-1)
		}
	}
	glog.V(1).Infof("...done in %v", time.Since(start))

	if len(overrides) != 0 {
		start = time.Now()
		glog.V(1).Info("applying overrides...")
		dict.Override(overrides)
		glog.V(1).Infof("...done in %v", time.Since(start))
	}

	cache := cvefeed.NewCache(dict).SetRequireVersion(cfg.requireVersion).SetMaxSize(cfg.cacheSize)

	if cfg.indexedDict {
		start = time.Now()
		glog.V(1).Info("indexing the dictionary...")
		cache.Idx = cvefeed.NewIndex(dict)
		glog.V(1).Infof("...done in %v", time.Since(start))
		if glog.V(2) {
			var named, total int
			for k, v := range cache.Idx {
				if k != wfn.Any {
					named += len(v)
				}
				total += len(v)
			}
			glog.Infof("%d out of %d records are named", named, total)
		}
	}

	if cfg.cpuProfile != "" {
		f, err := os.Create(cfg.cpuProfile)
		if err != nil {
			glog.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	done := processInput(os.Stdin, os.Stdout, cache, cfg)

	if cfg.memProfile != "" {
		f, err := os.Create(cfg.memProfile)
		if err != nil {
			glog.Fatal(err)
		}
		runtime.GC()
		if err = pprof.WriteHeapProfile(f); err != nil {
			glog.Errorf("couldn't write heap profile: %v", err)
		}
		f.Close()
	}

	<-done
}
