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
	"github.com/jokLiu/nvdtools/wfn"
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
