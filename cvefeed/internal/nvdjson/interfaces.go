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

	"github.com/jokLiu/nvdtools/cvefeed/internal/iface"
	"github.com/jokLiu/nvdtools/wfn"
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
			if cpeNode.VersionStartIncluding != "" && strings.Compare(ver, cpeNode.VersionStartIncluding) < 0 {
				continue
			}
			if cpeNode.VersionStartExcluding != "" && strings.Compare(ver, cpeNode.VersionStartExcluding) <= 0 {
				continue
			}
			if cpeNode.VersionEndIncluding != "" && strings.Compare(ver, cpeNode.VersionEndIncluding) > 0 {
				continue
			}
			if cpeNode.VersionEndExcluding != "" && strings.Compare(ver, cpeNode.VersionEndExcluding) >= 0 {
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
