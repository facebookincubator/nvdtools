// Package nvdxml defines the types and methods necessary to parse
// CPE Language specification as per https://csrc.nist.gov/schema/cpe/2.3/cpe-language_2.3.xsd
// The implementation is not full, only parts required to parse NVD vulnerability feed are implemented
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
package nvdxml

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/jokLiu/nvdtools/cvefeed/internal/iface"
)

// Parse parses dictionary from NVD vulnerability feed XML
func Parse(in io.Reader) ([]iface.CVEItem, error) {
	var feed NVDFeed
	d := xml.NewDecoder(in)
	if err := d.Decode(&feed); err != nil {
		return nil, fmt.Errorf("nvdxml.Load: parse error: %v", err)
	}
	return Reparse(feed.Entries), nil
}
