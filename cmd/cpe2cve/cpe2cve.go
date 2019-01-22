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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jokLiu/nvdtools/cvefeed"
	"github.com/jokLiu/nvdtools/wfn"
	"github.com/golang/glog"
)

// custom type to be recognized by flag.Parse()
type fieldsToSkip map[int]struct{}

// skipFields removes elements from  fields slice as per config
// NB!: modifies the underlying array of fields slice
func (fs fieldsToSkip) skipFields(fields []string) []string {
	j := 0
	for i := 0; i < len(fields); i++ {
		if _, ok := fs[i]; ok {
			continue
		}
		fields[j] = fields[i]
		j++
	}
	return fields[:j]
}

// appendAt appends and element to a slice at position at after skipping configured fields
// NB!: modifies the underlying array of to slice
func (fs fieldsToSkip) appendAt(to []string, args ...interface{}) []string {
	to = fs.skipFields(to)
	fields := map[int]string{}
	keys := make([]int, 0, len(args)/2)
	pos := -1
	for _, arg := range args {
		switch arg.(type) {
		case int:
			pos = arg.(int)
			keys = append(keys, pos)
		case string:
			if pos == -1 {
				panic("appendAt: string field was not prepended by position")
			}
			fields[pos] = arg.(string)
			pos = -1
		default:
			panic(fmt.Sprintf("appendAt: unsupported type %T", arg))
		}
	}
	sort.Ints(keys)
	for _, at := range keys {
		if at > len(to) {
			at = len(to)
		}
		out := make([]string, 0, len(to)+1)
		out = append(out, to[:at]...)
		out = append(out, fields[at])
		out = append(out, to[at:]...)
		to = out
	}
	return to
}

// part of flag.Value interface implementation
func (fs fieldsToSkip) String() string {
	fss := make([]string, 0, len(fs))
	for i := range fs {
		fss = append(fss, fmt.Sprintf("%d", i+1))
	}
	return strings.Join(fss, ",")
}

// part of flag.Value interface implementation
func (fs *fieldsToSkip) Set(val string) error {
	if *fs == nil {
		*fs = fieldsToSkip{}
	}
	for _, v := range strings.Split(val, ",") {
		n, err := strconv.Atoi(v)
		if err != nil {
			return err
		}
		if n < 1 {
			return fmt.Errorf("illegal field index %d", n)
		}
		(*fs)[n-1] = struct{}{}
	}
	return nil
}

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
	flag.Var(&c.skip, "e", "comma separated list of fields to erase from output; starts at 1; processed before the vulnerablitie field added")
	flag.BoolVar(&c.indexedDict, "idxd", false, "build and use an index for CVE dictionary: increases the processing speed, but might miss some matches")
	flag.BoolVar(&c.requireVersion, "require_version", false, "ignore matches of CPEs with version ANY")
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
	var dict cvefeed.Dictionary
	var err error
	switch cfg.feedFormat {
	case "xml":
		dict, err = cvefeed.LoadXMLDictionary(flag.Args()...)
	case "json":
		dict, err = cvefeed.LoadJSONDictionary(flag.Args()...)
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
