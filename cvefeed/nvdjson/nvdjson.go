// Package nvdjson defines the types and methods necessary to parse
// CVE Language specification as per https://csrc.nist.gov/schema/nvd/feed/0.1/nvd_cve_feed_json_0.1_beta.schema
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

// Package nvdjson provides a parser for the NVD JSON feed format.
package nvdjson

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/facebookincubator/nvdtools/cvefeed/nvdcommon"
)

// Parse parses dictionary from NVD vulnerability feed JSON
func Parse(in io.Reader) ([]nvdcommon.CVEItem, error) {
	var root NVDCVEFeedJSON10
	err := json.NewDecoder(in).Decode(&root)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return reparse(&root)
}

func reparse(root *NVDCVEFeedJSON10) ([]nvdcommon.CVEItem, error) {
	srcItems := root.CVEItems
	if len(srcItems) == 0 {
		return nil, fmt.Errorf("NVD CVE JSON feed had no CVE_Items element")
	}
	items := make([]nvdcommon.CVEItem, 0, len(srcItems))
	for _, item := range srcItems {
		if item == nil || item.Configurations == nil {
			continue
		}
		for _, node := range item.Configurations.Nodes {
			reparseLogicalTest(node)
			item.Configurations.nvdcommonNodes = append(item.Configurations.nvdcommonNodes, nvdcommon.LogicalTest(node))
		}
		items = append(items, nvdcommon.CVEItem(item))
	}
	return items, nil
}

func reparseLogicalTest(node *NVDCVEFeedJSON10DefNode) {
	if node == nil {
		return
	}
	for _, innerNode := range node.Children {
		reparseLogicalTest(innerNode)
	}
	node.nvdcommonChildren = node.InnerTests()
	node.wfnCPEs = node.CPEs()
}
