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
	"fmt"
	"log"
	"time"

	"github.com/facebookincubator/nvdtools/cvefeed/nvdcommon"
	"github.com/facebookincubator/nvdtools/wfn"

	dstSchema "github.com/facebookincubator/nvdtools/cvefeed/jsonschema"
	srcSchema "github.com/facebookincubator/nvdtools/providers/rbs/schema"
)

const (
	cveDataVersion = "4.0"
	timeLayout     = "2006-01-02T15:04:05Z"
)

// Convert converts iDefense vulnerability to NVD format
func Convert(input <-chan *srcSchema.Vulnerability) *dstSchema.NVDCVEFeedJSON10 {
	var feed dstSchema.NVDCVEFeedJSON10
	for vuln := range input {
		converted, err := convert(vuln)
		if err != nil {
			log.Println(err)
			continue
		}
		feed.CVEItems = append(feed.CVEItems, converted)
	}
	return &feed
}

func convert(item *srcSchema.Vulnerability) (*dstSchema.NVDCVEFeedJSON10DefCVEItem, error) {
	lastModifiedDate, err := convertTime(item.VulndbLastModified)
	if err != nil {
		return nil, fmt.Errorf("can't convert last modified date: %v", err)
	}
	publishedDate, err := convertTime(item.VulndbPublishedDate)
	if err != nil {
		return nil, fmt.Errorf("can't convert published date: %v", err)
	}
	impact, err := makeImpact(item)
	if err != nil {
		return nil, fmt.Errorf("can't create impact: %v", err)
	}

	nvdItem := dstSchema.NVDCVEFeedJSON10DefCVEItem{
		CVE: &dstSchema.CVEJSON40{
			CVEDataMeta: &dstSchema.CVEJSON40CVEDataMeta{
				ID:       makeID(item),
				ASSIGNER: "rbs",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: cveDataVersion,
			Description: &dstSchema.CVEJSON40Description{
				DescriptionData: []*dstSchema.CVEJSON40LangString{
					{Lang: "en", Value: item.Title},
					{Lang: "en", Value: item.Description},
				},
			},
			Problemtype: &dstSchema.CVEJSON40Problemtype{},
			References:  makeReferences(item),
		},
		Configurations:   makeConfigurations(item),
		Impact:           impact,
		LastModifiedDate: lastModifiedDate,
		PublishedDate:    publishedDate,
	}

	addNVDData(&nvdItem, item.NVDAdditionalInfo)

	return &nvdItem, nil
}

func makeID(item *srcSchema.Vulnerability) string {
	return fmt.Sprintf("rbs-%d", item.VulndbID)
}

func makeReferences(item *srcSchema.Vulnerability) *dstSchema.CVEJSON40References {
	if len(item.ExtReferences) == 0 {
		return nil
	}

	var refsData []*dstSchema.CVEJSON40Reference

	for _, ref := range item.ExtReferences {
		refsData = append(refsData, &dstSchema.CVEJSON40Reference{
			Name: ref.Type,
			URL:  ref.Value,
		})
	}

	return &dstSchema.CVEJSON40References{
		ReferenceData: refsData,
	}
}

func makeConfigurations(item *srcSchema.Vulnerability) *dstSchema.NVDCVEFeedJSON10DefConfigurations {
	var matches []*dstSchema.NVDCVEFeedJSON10DefCPEMatch

	for _, vendor := range item.Vendors {
		for _, product := range vendor.Products {
			for _, version := range product.Versions {
				if version.Affected == "false" {
					continue
				}
				for _, cpe := range version.CPEs {
					c, err := normalizeCPE(cpe.CPE)
					if err != nil {
						log.Printf("couldn't normalize cpe %q: %v", cpe.CPE, err)
						continue
					}
					match := &dstSchema.NVDCVEFeedJSON10DefCPEMatch{
						Cpe23Uri:   c,
						Vulnerable: true,
					}
					matches = append(matches, match)
				}
			}
		}
	}

	conf := dstSchema.NVDCVEFeedJSON10DefConfigurations{
		CVEDataVersion: cveDataVersion,
		Nodes: []*dstSchema.NVDCVEFeedJSON10DefNode{
			&dstSchema.NVDCVEFeedJSON10DefNode{
				CPEMatch: matches,
				Operator: "OR",
			},
		},
	}

	return &conf
}

func makeImpact(item *srcSchema.Vulnerability) (*dstSchema.NVDCVEFeedJSON10DefImpact, error) {
	// TODO they don't have cvss vectors. they do have parts of it so we could construct them
	// using our library nvdtools/cvss{2,3}/...

	l2 := len(item.CVSSMetrics)
	l3 := len(item.CVSS3Metrics)

	if l2 == 0 && l3 == 0 {
		return nil, fmt.Errorf("no cvss metrics found")
	}

	var cvssv2 *dstSchema.CVSSV20
	if l2 != 0 {
		cvssv2 = &dstSchema.CVSSV20{BaseScore: item.CVSSMetrics[l2-1].Score}
	}

	var cvssv3 *dstSchema.CVSSV30
	if l3 != 0 {
		cvssv3 = &dstSchema.CVSSV30{BaseScore: item.CVSS3Metrics[l3-1].Score}
	}

	impact := dstSchema.NVDCVEFeedJSON10DefImpact{
		BaseMetricV2: &dstSchema.NVDCVEFeedJSON10DefImpactBaseMetricV2{CVSSV2: cvssv2},
		BaseMetricV3: &dstSchema.NVDCVEFeedJSON10DefImpactBaseMetricV3{CVSSV3: cvssv3},
	}

	return &impact, nil
}

func convertTime(rbsTime string) (string, error) {
	if rbsTime == "" { // handle no time
		return "", nil
	}
	t, err := time.Parse(timeLayout, rbsTime)
	if err != nil { // should be parsable
		return "", err
	}
	return t.Format(nvdcommon.TimeLayout), nil
}

func normalizeCPE(cpe string) (string, error) {
	attrs, err := wfn.UnbindFmtString(cpe)
	if err != nil {
		return "", fmt.Errorf("can't unbind CPE URI: %v", err)
	}
	if attrs.Version == "Unspecified" {
		attrs.Version = wfn.Any
	}
	return attrs.BindToFmtString(), nil
}

func addNVDData(nvdItem *dstSchema.NVDCVEFeedJSON10DefCVEItem, additional []*srcSchema.NVDAdditionalInfo) {
	addRef := func(name, url string) {
		nvdItem.CVE.References.ReferenceData = append(
			nvdItem.CVE.References.ReferenceData,
			&dstSchema.CVEJSON40Reference{
				Name: name,
				URL:  url,
			},
		)
	}

	addCWE := func(cwe string) {
		nvdItem.CVE.Problemtype.ProblemtypeData = append(
			nvdItem.CVE.Problemtype.ProblemtypeData,
			&dstSchema.CVEJSON40ProblemtypeProblemtypeData{

				Description: []*dstSchema.CVEJSON40LangString{
					{Lang: "en", Value: cwe},
				},
			},
		)
	}

	for _, add := range additional {
		addRef(add.CVEID, "")
		for _, ref := range add.References {
			addRef(ref.Name, ref.URL)
		}
		addCWE(add.CWEID)
	}
}
