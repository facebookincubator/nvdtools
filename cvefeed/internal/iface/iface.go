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
package iface

import (
	"github.com/facebookincubator/nvdtools/wfn"
)

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

	z := mergeCVEItem{
		id:     x.CVEID(),
		config: []LogicalTest{mergeOp},
	}

	return z
}

type mergeCVEItem struct {
	id     string
	config []LogicalTest
}

func (i mergeCVEItem) CVEID() string {
	return i.id
}

func (i mergeCVEItem) Config() []LogicalTest {
	return i.config
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
