// Package iface defines interfaces CVE feed implements, no matter the format (XML, JSON...)
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

// Package nvdcommon provides a common interface for NVD JSON and XML feeds.
package nvdcommon

import (
	"github.com/facebookincubator/nvdtools/wfn"
)

// TimeLayout is the layout of NVD CVE timestamps.
const TimeLayout = "2006-01-02T15:04Z"

// LogicalTest describes logical test performed during matching
type LogicalTest interface {
	LogicalOperator() string // "and", "or", "eq"
	NegateIfNeeded(bool) bool
	InnerTests() []LogicalTest
	MatchPlatform(platform *wfn.Attributes, requireVersion bool) bool
	CPEs() []*wfn.Attributes
}

// CVEItem is an interface that provides access to CVE data from vulnerability feed
type CVEItem interface {
	CVEID() string
	Config() []LogicalTest
	ProblemTypes() []string
	CVSS20base() float64
	CVSS30base() float64
}

// MergeCVEItems combines two CVEItems:
// resulted CVEItem inherits all mutually exclusive methods (e.g. CVEID()) from CVEItem x;
// but Configuration() call returns rule equal to x.LogicalTests AND NOT y.LogicalTests
func MergeCVEItems(x, y CVEItem) CVEItem {
	xOp := mergeOperator{
		inners: x.Config(),
	}
	yOp := mergeOperator{
		negate: true,
		inners: y.Config(),
	}
	mergeOp := mergeOperator{
		override: true,
		inners:   []LogicalTest{&xOp, &yOp},
	}

	// CWE merging: append + unique
	var cwes []string
	set := map[string]bool{}
	for _, cwe := range x.ProblemTypes() {
		set[cwe] = true
	}
	for cwe := range set {
		cwes = append(cwes, cwe)
	}
	for _, cwe := range y.ProblemTypes() {
		if _, ok := set[cwe]; !ok {
			cwes = append(cwes, cwe)
		}
	}

	// CVSS score merging: larger wins
	cvss20, cvss30 := x.CVSS20base(), x.CVSS30base()
	if cvss20 < y.CVSS20base() {
		cvss20 = y.CVSS20base()
	}
	if cvss30 < y.CVSS30base() {
		cvss30 = y.CVSS30base()
	}

	z := mergeCVEItem{
		id:           x.CVEID(),
		problemTypes: cwes,
		cvss20base:   cvss20,
		cvss30base:   cvss30,
		config:       []LogicalTest{mergeOp},
	}

	return z
}

type mergeCVEItem struct {
	id                     string
	config                 []LogicalTest
	problemTypes           []string
	cvss20base, cvss30base float64
}

func (i mergeCVEItem) CVEID() string {
	return i.id
}

func (i mergeCVEItem) Config() []LogicalTest {
	return i.config
}

func (i mergeCVEItem) ProblemTypes() []string {
	return i.problemTypes
}

func (i mergeCVEItem) CVSS20base() float64 {
	return i.cvss20base
}

func (i mergeCVEItem) CVSS30base() float64 {
	return i.cvss30base
}

type mergeOperator struct {
	override, negate bool
	inners           []LogicalTest
}

func (mo mergeOperator) LogicalOperator() string {
	if mo.override {
		return "and"
	}
	return "or"
}

func (mo mergeOperator) NegateIfNeeded(b bool) bool {
	if mo.negate {
		return !b
	}
	return b
}

func (mo mergeOperator) InnerTests() []LogicalTest {
	return mo.inners
}

func (mo mergeOperator) MatchPlatform(_ *wfn.Attributes, _ bool) bool {
	return false
}

func (mo mergeOperator) CPEs() []*wfn.Attributes {
	return nil
}
