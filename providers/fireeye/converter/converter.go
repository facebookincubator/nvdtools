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

package converter

import (
	"strings"

	dstSchema "github.com/facebookincubator/nvdtools/cvefeed/nvdjson"
	srcSchema "github.com/facebookincubator/nvdtools/providers/fireeye/schema"
)

const (
	cveDataVersion = "4.0"
)

// Convert converts FireEye vulnerability to NVD format
func Convert(items []*srcSchema.FireeyeVulnerability) dstSchema.NVDCVEFeedJSON10 {
	cveItems := make([]*dstSchema.NVDCVEFeedJSON10DefCVEItem, len(items))
	for idx, item := range items {
		cveItems[idx] = convert(item)
	}
	return dstSchema.NVDCVEFeedJSON10{CVEItems: cveItems}
}

func convert(item *srcSchema.FireeyeVulnerability) *dstSchema.NVDCVEFeedJSON10DefCVEItem {
	return &dstSchema.NVDCVEFeedJSON10DefCVEItem{
		CVE: &dstSchema.CVEJSON40{
			CVEDataMeta: &dstSchema.CVEJSON40CVEDataMeta{
				ID:       makeID(item),
				ASSIGNER: "fireeye",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: cveDataVersion,
			Description: &dstSchema.CVEJSON40Description{
				DescriptionData: []*dstSchema.CVEJSON40LangString{
					{Lang: "en", Value: item.Title},
				},
			},
			References: makeReferences(item),
		},
		Configurations: makeConfigurations(item),
		Impact: &dstSchema.NVDCVEFeedJSON10DefImpact{
			BaseMetricV2: &dstSchema.NVDCVEFeedJSON10DefImpactBaseMetricV2{
				CVSSV2: &dstSchema.CVSSV20{
					BaseScore:     extractCVSSBaseScore(item),
					TemporalScore: extractCVSSTemporalScore(item),
					VectorString:  extractCVSSVectorString(item),
				},
			},
		},
		LastModifiedDate: convertTime(item.PublishDate),
		PublishedDate:    convertTime(item.Version1PublishDate),
	}
}

func makeID(item *srcSchema.FireeyeVulnerability) string {
	return "fireeye-" + item.ReportID
}

func makeReferences(item *srcSchema.FireeyeVulnerability) *dstSchema.CVEJSON40References {
	var refsData []*dstSchema.CVEJSON40Reference
	addRef := func(name, url string) {
		refsData = append(refsData, &dstSchema.CVEJSON40Reference{
			Name: name,
			URL:  url,
		})
	}

	addRef("FireEye report API link", item.ReportLink)
	addRef("FireEye web link", item.WebLink)
	for _, cve := range item.CVEIds {
		for _, cveid := range strings.Split(cve, ",") {
			addRef(cveid, "")
		}
	}

	return &dstSchema.CVEJSON40References{
		ReferenceData: refsData,
	}
}

func makeConfigurations(item *srcSchema.FireeyeVulnerability) *dstSchema.NVDCVEFeedJSON10DefConfigurations {
	var matches []*dstSchema.NVDCVEFeedJSON10DefCPEMatch
	for _, cpe := range extractCPEs(item) {
		matches = append(matches, &dstSchema.NVDCVEFeedJSON10DefCPEMatch{
			Cpe23Uri:   cpe,
			Vulnerable: true,
		})
	}

	return &dstSchema.NVDCVEFeedJSON10DefConfigurations{
		CVEDataVersion: cveDataVersion,
		Nodes: []*dstSchema.NVDCVEFeedJSON10DefNode{
			&dstSchema.NVDCVEFeedJSON10DefNode{
				CPEMatch: matches,
				Operator: "OR",
			},
		},
	}
}
