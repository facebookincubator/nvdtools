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

package nvdjson

import (
	"fmt"
	"strings"

	"github.com/facebookincubator/nvdtools/cvefeed/jsonschema"
	"github.com/facebookincubator/nvdtools/cvefeed/nvdcommon"
	"github.com/facebookincubator/nvdtools/wfn"
)

// cpeMatch is a wrapper around the actual NVDCVEFeedJSON10DefCPEMatch
type cpeMatch struct {
	attrs                 *wfn.Attributes
	versionEndExcluding   string
	versionEndIncluding   string
	versionStartExcluding string
	versionStartIncluding string
}

func newCpeMatch(nvdMatch *jsonschema.NVDCVEFeedJSON10DefCPEMatch) (*cpeMatch, error) {
	var match cpeMatch

	parse := func(uri string) (*wfn.Attributes, error) {
		if uri == "" {
			return nil, fmt.Errorf("can't parse empty uri")
		}
		return wfn.Parse(uri)
	}

	// parse
	var err error
	if match.attrs, err = parse(nvdMatch.Cpe23Uri); err != nil {
		if match.attrs, err = parse(nvdMatch.Cpe22Uri); err != nil {
			return nil, fmt.Errorf("unable to parse both cpe2.2 and cpe2.3")
		}
	}

	match.versionEndExcluding = nvdMatch.VersionEndExcluding
	match.versionEndIncluding = nvdMatch.VersionEndIncluding
	match.versionStartExcluding = nvdMatch.VersionStartExcluding
	match.versionStartIncluding = nvdMatch.VersionStartIncluding

	return &match, nil
}

// node is a wrapper around the actual NVDCVEFeedJSON10DefNode
type node struct {
	nvdNode  *jsonschema.NVDCVEFeedJSON10DefNode
	children []nvdcommon.LogicalTest
	matches  []*cpeMatch
	cpes     []*wfn.Attributes // uses pointers to matches.attrs
}

func newNode(nvdNode *jsonschema.NVDCVEFeedJSON10DefNode) *node {
	n := &node{
		nvdNode:  nvdNode,
		children: make([]nvdcommon.LogicalTest, 0, len(nvdNode.Children)),
		matches:  make([]*cpeMatch, 0, len(nvdNode.CPEMatch)),
		cpes:     make([]*wfn.Attributes, 0, len(nvdNode.CPEMatch)),
	}

	// copy chiltren
	for _, child := range nvdNode.Children {
		n.children = append(n.children, newNode(child))
	}

	// parse cpe matching
	for _, nvdMatch := range nvdNode.CPEMatch {
		if match, err := newCpeMatch(nvdMatch); err == nil {
			n.matches = append(n.matches, match)
			n.cpes = append(n.cpes, match.attrs)
		}
	}

	return n
}

// LogicalOperator implements part of cvefeed.LogicalTest interface
func (n *node) LogicalOperator() string {
	if n == nil {
		return ""
	}
	return n.nvdNode.Operator
}

// NegateIfNeeded implements part of cvefeed.LogicalTest interface
func (n *node) NegateIfNeeded(b bool) bool {
	if n == nil || !n.nvdNode.Negate {
		return b
	}
	return !b
}

// InnerTests implements part of cvefeed.LogicalTest interface
func (n *node) InnerTests() []nvdcommon.LogicalTest {
	if n == nil {
		return nil
	}
	return n.children
}

// CPEs implements part of cvefeed.LogicalTest interface
func (n *node) CPEs() []*wfn.Attributes {
	if n == nil {
		return nil
	}
	return n.cpes
}

// MatchPlatform implements part of cvefeed.LogicalTest interface
func (n *node) MatchPlatform(platform *wfn.Attributes, requireVersion bool) bool {
	if n == nil {
		return false
	}
	ver := wfn.StripSlashes(platform.Version)
	for i, match := range n.matches {
		if match == nil {
			fmt.Println(i)
			fmt.Printf("%v\n", *n)
		}
		// Not sure if this is needed, in the feed whenever there is a version constraints, version attributes is already ANY,
		// but better safe, than sorry.
		if match.versionStartIncluding != "" || match.versionStartExcluding != "" ||
			match.versionEndIncluding != "" || match.versionEndExcluding != "" {
			match.attrs.Version = wfn.Any
		} else if requireVersion && match.attrs.Version == wfn.Any {
			continue
		}
		if wfn.Match(match.attrs, platform) {
			if platform.Version == wfn.Any || platform.Version == wfn.NA {
				// logical value of N/A only matches logical value of ANY, so technically, this should
				// return platform.Version == wfn.Any || cpe.Version == wfn.Any
				// but these checks have already been performed by wfn.Match() above
				return true
			}
			if match.versionStartIncluding == "" && match.versionStartExcluding == "" &&
				match.versionEndIncluding == "" && match.versionEndExcluding == "" {
				return true
			}
			if match.attrs.Version == wfn.NA {
				return false
			}
			if match.versionStartIncluding != "" && smartVerCmp(ver, match.versionStartIncluding) < 0 {
				continue
			}
			if match.versionStartExcluding != "" && smartVerCmp(ver, match.versionStartExcluding) <= 0 {
				continue
			}
			if match.versionEndIncluding != "" && smartVerCmp(ver, match.versionEndIncluding) > 0 {
				continue
			}
			if match.versionEndExcluding != "" && smartVerCmp(ver, match.versionEndExcluding) >= 0 {
				continue
			}
			return true
		}
	}
	return false
}

// cveItem is a wrapper around the actual NVDCVEFeedJSON10DefCVEItem
type cveItem struct {
	cveItem *jsonschema.NVDCVEFeedJSON10DefCVEItem
	nodes   []nvdcommon.LogicalTest
}

// newCveItem is a helper function for creating
func newCveItem(json *jsonschema.NVDCVEFeedJSON10DefCVEItem) nvdcommon.CVEItem {
	item := &cveItem{cveItem: json}
	for _, n := range item.cveItem.Configurations.Nodes {
		item.nodes = append(item.nodes, newNode(n))
	}
	return item
}

// implement nvdcommon.CVEItem

// CVEID returns the identifier of the vulnerability (e.g. CVE).
func (i *cveItem) CVEID() string {
	if i == nil {
		return ""
	}
	return i.cveItem.CVE.CVEDataMeta.ID
}

// Config returns a set of tests that identify vulnerable platform.
func (i *cveItem) Config() []nvdcommon.LogicalTest {
	if i == nil {
		return nil
	}
	return i.nodes
}

// ProblemTypes returns weakness types associated with vulnerability (e.g. CWE)
func (i *cveItem) ProblemTypes() []string {
	var cwes []string
	if i.cveItem.CVE == nil || i.cveItem.CVE.CVEDataMeta == nil || i.cveItem.CVE.CVEDataMeta.ID == "" {
		return nil
	}

	if i.cveItem.CVE.Problemtype != nil {
		for _, pt := range i.cveItem.CVE.Problemtype.ProblemtypeData {
			if pt != nil {
				cwe := getLangStr(pt.Description)
				cwes = append(cwes, cwe)
			}
		}
	}
	return cwes
}

// CVSS20base returns CVSS 2.0 base score of vulnerability
func (i *cveItem) CVSS20base() float64 {
	if i.cveItem.Impact != nil && i.cveItem.Impact.BaseMetricV2 != nil && i.cveItem.Impact.BaseMetricV2.CVSSV2 != nil {
		return i.cveItem.Impact.BaseMetricV2.CVSSV2.BaseScore
	}
	return 0.0
}

// CVSS30base returns CVSS 3.0 base score of vulnerability
func (i *cveItem) CVSS30base() float64 {
	// find CVSSv3 base score
	if i.cveItem.Impact != nil && i.cveItem.Impact.BaseMetricV3 != nil && i.cveItem.Impact.BaseMetricV3.CVSSV3 != nil {
		return i.cveItem.Impact.BaseMetricV3.CVSSV3.BaseScore
	}
	return 0.0
}

// smartVerCmp compares stringified versions of software.
// It tries to do the right thing for any type of versioning,
// assuming v1 and v2 have the same version convension.
// It will return meaningful result for "95SE" vs "98SP1" or for "16.3.2" vs. "3.7.0",
// but not for "2000" vs "11.7".
// Returns -1 if v1 < v2, 1 if v1 > v2 and 0 if v1 == v2.
func smartVerCmp(v1, v2 string) int {
	for s1, s2 := v1, v2; len(s1) > 0 && len(s2) > 0; {
		num1, cmpTo1, skip1 := parseVerParts(s1)
		num2, cmpTo2, skip2 := parseVerParts(s2)
		if num1 > num2 {
			return 1
		}
		if num2 > num1 {
			return -1
		}
		if cmp := strings.Compare(s1[:cmpTo1], s2[:cmpTo2]); cmp != 0 {
			return cmp
		}
		s1 = s1[skip1:]
		s2 = s2[skip2:]
	}
	// everything is equal so far, the longest wins
	if len(v1) > len(v2) {
		return 1
	}
	if len(v2) > len(v1) {
		return -1
	}
	return 0
}

// parseVerParts returns the length of consecutive run of digits in the beginning of the string,
// the last non-separator chararcted (which should be compared), and index at which the version part (major, minor etc.) ends,
// i.e. the position of the dot or end of the line.
// E.g. parseVerParts("11b.4.16-New_Year_Edition") will return (2, 3, 4)
func parseVerParts(v string) (int, int, int) {
	var num int
	for num = 0; num < len(v); num++ {
		if v[num] < '0' || v[num] > '9' {
			break
		}
	}
	if num == len(v) {
		return num, num, num
	}
	// Any punctuation separates the parts.
	skip := strings.IndexFunc(v, func(b rune) bool {
		// !"#$%&'()*+,-./ are dec 33 to 47, :;<=>?@ are dec 58 to 64, [\]^_` are dec 91 to 96 and {|}~ are dec 123 to 126.
		// So, punctuation is in dec 33-126 range except 48-57, 65-90 and 97-122 gaps.
		// This inverse logic allows for early short-circuting for most of the chars and shaves ~20ns in benchmarks.
		return b >= '!' && b <= '~' &&
			!(b > '/' && b < ':' ||
				b > '@' && b < '[' ||
				b > '`' && b < '{')
	})
	if skip == -1 {
		return num, len(v), len(v)
	}
	return num, skip, skip + 1
}

func getLangStr(lss []*jsonschema.CVEJSON40LangString) string {
	var s string
	for _, ls := range lss {
		if ls == nil {
			continue
		}
		s = ls.Value
		if ls.Lang == "en" {
			break
		}
	}
	return s
}
