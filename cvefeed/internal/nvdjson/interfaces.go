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
	"strings"

	"github.com/facebookincubator/nvdtools/cvefeed/internal/iface"
	"github.com/facebookincubator/nvdtools/wfn"
)

// NVDCVEFeedJSON10DefCVEItem is a CVEItem

// CVEID implements part of cvefeed.CVEItem interface
func (i *NVDCVEFeedJSON10DefCVEItem) CVEID() string {
	return i.CVE.CVEDataMeta.ID
}

// Config implements part of cvefeed.CVEItem interface
func (i *NVDCVEFeedJSON10DefCVEItem) Config() []iface.LogicalTest {
	return i.Configurations.ifaceNodes
}

// NVDCVEFeedJSON10DefNode is a LogicalTest

// LogicalOperator implements part of cvefeed.LogicalTest interface
func (n *NVDCVEFeedJSON10DefNode) LogicalOperator() string {
	return n.Operator
}

// NegateIfNeeded implements part of cvefeed.LogicalTest interface
func (n *NVDCVEFeedJSON10DefNode) NegateIfNeeded(b bool) bool {
	if n.Negate {
		return !b
	}
	return b
}

// InnerTests implements part of cvefeed.LogicalTest interface
func (n *NVDCVEFeedJSON10DefNode) InnerTests() []iface.LogicalTest {
	if len(n.ifaceChildren) != 0 {
		return n.ifaceChildren
	}
	if len(n.Children) == 0 {
		return nil
	}
	children := make([]iface.LogicalTest, len(n.Children))
	for i, child := range n.Children {
		children[i] = iface.LogicalTest(child)
	}
	return children
}

// CPEs implements part of cvefeed.LogicalTest interface
func (n *NVDCVEFeedJSON10DefNode) CPEs() []*wfn.Attributes {
	if len(n.wfnCPEs) != 0 {
		return n.wfnCPEs
	}
	if len(n.CPEMatch) == 0 {
		return nil
	}
	cpes := make([]*wfn.Attributes, len(n.CPEMatch))
	for i, node := range n.CPEMatch {
		cpe, err := node2CPE(node)
		if err == nil {
			cpes[i] = cpe
		}
	}
	return cpes
}

// MatchPlatform implements part of cvefeed.LogicalTest interface
func (n *NVDCVEFeedJSON10DefNode) MatchPlatform(platform *wfn.Attributes, requireVersion bool) bool {
	for _, cpeNode := range n.CPEMatch {
		cpe, err := node2CPE(cpeNode)
		if err != nil {
			continue
		}
		// Not sure if this is needed, in the feed whenever there is a version constraints, version attributes is already ANY,
		// but better safe, than sorry.
		if cpeNode.VersionStartIncluding != "" || cpeNode.VersionStartExcluding != "" ||
			cpeNode.VersionEndIncluding != "" || cpeNode.VersionEndExcluding != "" {
			cpe.Version = wfn.Any
		} else if requireVersion && cpe.Version == wfn.Any {
			continue
		}
		if wfn.Match(cpe, platform) {
			if platform.Version == wfn.Any || platform.Version == wfn.NA {
				// logical value of N/A only matches logical value of ANY, so technically, this should
				// return platform.Version == wfn.Any || cpe.Version == wfn.Any
				// but these checks have already been performed by wfn.Match() above
				return true
			}
			if cpeNode.VersionStartIncluding == "" && cpeNode.VersionStartExcluding == "" &&
				cpeNode.VersionEndIncluding == "" && cpeNode.VersionEndExcluding == "" {
				return true
			}
			ver := wfn.StripSlashes(platform.Version)
			if cpeNode.VersionStartIncluding != "" && smartVerCmp(ver, cpeNode.VersionStartIncluding) < 0 {
				continue
			}
			if cpeNode.VersionStartExcluding != "" && smartVerCmp(ver, cpeNode.VersionStartExcluding) <= 0 {
				continue
			}
			if cpeNode.VersionEndIncluding != "" && smartVerCmp(ver, cpeNode.VersionEndIncluding) > 0 {
				continue
			}
			if cpeNode.VersionEndExcluding != "" && smartVerCmp(ver, cpeNode.VersionEndExcluding) >= 0 {
				continue
			}
			return true
		}
	}
	return false
}

func node2CPE(node *NVDCVEFeedJSON10DefCPEMatch) (*wfn.Attributes, error) {
	var err error
	if node.wfname != nil {
		return node.wfname, nil
	}
	uri := node.Cpe23Uri
	if uri == "" {
		uri = node.Cpe22Uri
	}
	node.wfname, err = wfn.Parse(uri)
	return node.wfname, err
}

// smartVerCmp compares stringified versions of software.
// It tries to do the right thing for any type of versioning,
// assuming v1 and v2 have the same version convension.
// It will return meaningful result for "95SE" vs "98SP1" or for "16.3.2" vs. "3.7.0",
// but not for "2000" vs "11.7".
// Returns -1 if v1 < v2, 1 if v1 > v2 and 0 if v1 == v2.
func smartVerCmp(v1, v2 string) int {
	for s1, s2 := v1, v2; len(s1) > 0 && len(s2) > 0; {
		num1, alpha1, skip1 := parseVerParts(v1)
		num2, alpha2, skip2 := parseVerParts(v2)
		if num1 > num2 {
			return 1
		}
		if num2 > num1 {
			return -1
		}
		if cmp := strings.Compare(alpha1, alpha2); cmp != 0 {
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

// parseVerParts returns the next comparable chunk of the version string v and
// how far it read into v to parse them. It tries to interpret the start of the string as a number.
// E.g. parseVerParts("11b.4.16-New_Year_Edition") will return (11, "b", 4)
func parseVerParts(v string) (num int, alpha string, skip int) {
	for skip = 0; skip < len(v) && v[skip] >= '0' && v[skip] <= '9'; skip++ {
		num = num*10 + int(v[skip]-'0')
	}
	alphaAt := skip
	if skip < len(v) {
		skip = strings.IndexRune(v, '.')
		if skip == -1 {
			skip = len(v)
		}
	}
	return num, v[alphaAt:skip], skip
}
