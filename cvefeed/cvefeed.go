// Package cvefeed defines types and methods necessary to parse NVD vulnerability
// feed and match an inventory of CPE names against it.
//
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
package cvefeed

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/jokLiu/nvdtools/cvefeed/internal/iface"
	"github.com/jokLiu/nvdtools/cvefeed/internal/nvdjson"
	"github.com/jokLiu/nvdtools/cvefeed/internal/nvdxml"
	"github.com/jokLiu/nvdtools/wfn"
)

// CVEItem is an interface that provides access to CVE data from vulnerability feed
//	type CVEItem interface {
//		CVE() string
//		Configuration() []LogicalTest
//	}
type CVEItem = iface.CVEItem

// LogicalTest describes logical test performed during matching
// type LogicalTest interface {
// 	LogicalOperator() string // "and", "or", "eq"
// 	NegateIfNeeded(bool) bool
// 	InnerTests() []LogicalTest
// 	MatchPlatform(platform *wfn.Attributes, requireVersion bool) bool
// 	CPEs() []*wfn.Attributes
// }
type LogicalTest = iface.LogicalTest

// ParseXML loads CVE feed from XML
func ParseXML(in io.Reader) ([]CVEItem, error) {
	feed, err := setupReader(in)
	if err != nil {
		return nil, fmt.Errorf("cvefeed.ParseXML: read error: %v", err)
	}
	defer feed.Close()
	return nvdxml.Parse(feed)
}

// ParseJSON loads CVE feed from JSON
func ParseJSON(in io.Reader) ([]CVEItem, error) {
	feed, err := setupReader(in)
	if err != nil {
		return nil, fmt.Errorf("cvefeed.ParseJSON: read error: %v", err)
	}
	defer feed.Close()
	return nvdjson.Parse(feed)
}

func setupReader(in io.Reader) (src io.ReadCloser, err error) {
	r := bufio.NewReader(in)
	header, err := r.Peek(2)
	if err != nil {
		return nil, err
	}
	// assume plain text first
	src = ioutil.NopCloser(r)
	// replace with gzip.Reader if gzip'ed
	if header[0] == 0x1f && header[1] == 0x8b { // file is gzip'ed
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		src = zr
	}
	// TODO: maybe support .zip
	return src, nil
}

// Match matches list of software in inventory to a number of rules;
// returns the CPE names that matched and the boolean result of the match.
// If requireVersion is true, the function ignores rules with no Version attribute.
func Match(inventory []*wfn.Attributes, rules []LogicalTest, requireVersion bool) ([]*wfn.Attributes, bool) {
	matches := make([]*wfn.Attributes, 0, len(inventory))
	matched := false
	for _, op := range rules {
		matched = matched || matchLogicalTest(&matches, inventory, op, requireVersion)
	}
	if matched {
		return append([]*wfn.Attributes{}, matches...), true
	}
	return nil, false
}

func matchLogicalTest(matches *[]*wfn.Attributes, inventory []*wfn.Attributes, op LogicalTest, requireVersion bool) bool {
	matched := false
	switch strings.ToLower(op.LogicalOperator()) {
	case "or":
		for _, o := range op.InnerTests() {
			if matchLogicalTest(matches, inventory, o, requireVersion) {
				return op.NegateIfNeeded(true)
			}
		}
	case "and":
		for _, o := range op.InnerTests() {
			if !matchLogicalTest(matches, inventory, o, requireVersion) {
				return op.NegateIfNeeded(false)
			}
			matched = true
		}
	}
	for _, name := range inventory {
		if op.MatchPlatform(name, requireVersion) {
			*matches = append(*matches, name)
			matched = true
		}
	}
	return op.NegateIfNeeded(matched)
}
