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
	"log"

	dstSchema "github.com/facebookincubator/nvdtools/cvefeed/nvdjson"
	srcSchema "github.com/facebookincubator/nvdtools/providers/flexera/schema"

	"github.com/pkg/errors"
)

const (
	cveDataVersion = "4.0"
)

// Convert converts Flexera advisories to NVD format
func Convert(input <-chan *srcSchema.FlexeraAdvisory) *dstSchema.NVDCVEFeedJSON10 {
	var feed dstSchema.NVDCVEFeedJSON10
	for adv := range input {
		converted, err := convert(adv)
		if err != nil {
			log.Println(err)
			continue
		}
		feed.CVEItems = append(feed.CVEItems, converted)
	}
	return &feed
}

func convert(item *srcSchema.FlexeraAdvisory) (*dstSchema.NVDCVEFeedJSON10DefCVEItem, error) {
	if item.Products == nil {
		return nil, errors.New("No products associated with advisory")
	}

	var cpes []string
	for _, product := range item.Products {
		if productCPEs, err := findCPEs(product); err == nil {
			cpes = append(cpes, productCPEs...)
		}
	}
	if len(cpes) == 0 {
		return nil, errors.New("No cpes associated with advisory")
	}

	lastModifiedDate, err := convertTime(item.ModifiedDate)
	if err != nil {
		return nil, err
	}

	publishedDate, err := convertTime(item.Released)
	if err != nil {
		return nil, err
	}

	return &dstSchema.NVDCVEFeedJSON10DefCVEItem{
		CVE: &dstSchema.CVEJSON40{
			CVEDataMeta: &dstSchema.CVEJSON40CVEDataMeta{
				ID:       makeID(item),
				ASSIGNER: "flexera",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: cveDataVersion,
			Description: &dstSchema.CVEJSON40Description{
				DescriptionData: []*dstSchema.CVEJSON40LangString{
					{Lang: "en", Value: item.Description},
				},
			},
			References: makeReferences(item),
		},
		Configurations:   makeConfigurations(cpes),
		Impact:           makeImpact(item),
		LastModifiedDate: lastModifiedDate,
		PublishedDate:    publishedDate,
	}, nil
}

func makeID(item *srcSchema.FlexeraAdvisory) string {
	return "flexera-" + item.AdvisoryIdentifier
}

func makeReferences(item *srcSchema.FlexeraAdvisory) *dstSchema.CVEJSON40References {
	var refsData []*dstSchema.CVEJSON40Reference
	addRef := func(name, url string) {
		refsData = append(refsData, &dstSchema.CVEJSON40Reference{
			Name: name,
			URL:  url,
		})
	}

	if item.References != nil {
		for _, ref := range item.References {
			addRef(ref.Description, ref.URL)
		}
	}

	if item.Vulnerabilities != nil {
		for _, vuln := range item.Vulnerabilities {
			addRef(vuln.Cve, "")
		}
	}

	return &dstSchema.CVEJSON40References{
		ReferenceData: refsData,
	}
}

func makeConfigurations(cpes []string) *dstSchema.NVDCVEFeedJSON10DefConfigurations {
	matches := make([]*dstSchema.NVDCVEFeedJSON10DefCPEMatch, len(cpes))
	for i, cpe := range cpes {
		matches[i] = &dstSchema.NVDCVEFeedJSON10DefCPEMatch{
			Cpe22Uri:   cpe,
			Vulnerable: true,
		}
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

func makeImpact(item *srcSchema.FlexeraAdvisory) *dstSchema.NVDCVEFeedJSON10DefImpact {
	var cvssv2 dstSchema.CVSSV20
	if item.CvssInfo != nil {
		cvssv2.BaseScore = item.CvssInfo.BaseScore
		cvssv2.VectorString = item.CvssInfo.Vector
	}
	var cvssv3 dstSchema.CVSSV30
	if item.Cvss3Info != nil {
		cvssv3.BaseScore = item.Cvss3Info.BaseScore
		cvssv3.VectorString = item.Cvss3Info.Vector
	}

	return &dstSchema.NVDCVEFeedJSON10DefImpact{
		BaseMetricV2: &dstSchema.NVDCVEFeedJSON10DefImpactBaseMetricV2{
			CVSSV2: &cvssv2,
		},
		BaseMetricV3: &dstSchema.NVDCVEFeedJSON10DefImpactBaseMetricV3{
			CVSSV3: &cvssv3,
		},
	}
}
