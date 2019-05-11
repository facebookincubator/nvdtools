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

	dstschema "github.com/facebookincubator/nvdtools/cvefeed/jsonschema"
	srcschema "github.com/facebookincubator/nvdtools/providers/snyk/jsonschema"

	"github.com/facebookincubator/nvdtools/wfn"
)

const (
	cveVersion = "4.0"
)

// Convert converts Snyk feed v4 to NVD CVE JSON 1.0.
func Convert(schema *srcschema.Snyk, lf map[string]bool) *dstschema.NVDCVEFeedJSON10 {
	feed := &dstschema.NVDCVEFeedJSON10{}
	for language, advisories := range *schema {
		if len(lf) > 0 && !lf[language] {
			log.Printf("skipping %s", language)
			continue
		}
		for _, advisory := range advisories {
			feed.CVEItems = append(feed.CVEItems, convert(advisory))
		}
	}
	return feed
}

func convert(advisory *srcschema.SnykAdvisory) *dstschema.NVDCVEFeedJSON10DefCVEItem {
	return &dstschema.NVDCVEFeedJSON10DefCVEItem{
		CVE: &dstschema.CVEJSON40{
			CVEDataMeta: &dstschema.CVEJSON40CVEDataMeta{
				ID:       advisory.ID,
				ASSIGNER: "snyk.io",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE", // TODO: maybe set this to SNYK-$LANG ?
			DataVersion: cveVersion,
			Description: &dstschema.CVEJSON40Description{
				DescriptionData: []*dstschema.CVEJSON40LangString{
					{
						Lang:  "en",
						Value: advisory.Description,
					},
				},
			},
			Problemtype: newProblemType(advisory),
			References:  newReferences(advisory),
		},
		Configurations:   newConfigurations(advisory),
		Impact:           newImpact(advisory),
		LastModifiedDate: snykTimeToNVD(advisory.ModificationTime),
		PublishedDate:    snykTimeToNVD(advisory.PublicationTime),
	}
}

func newProblemType(advisory *srcschema.SnykAdvisory) *dstschema.CVEJSON40Problemtype {
	if len(advisory.Cwes) == 0 {
		return nil
	}
	pt := &dstschema.CVEJSON40Problemtype{
		ProblemtypeData: []*dstschema.CVEJSON40ProblemtypeProblemtypeData{
			{
				Description: make([]*dstschema.CVEJSON40LangString, len(advisory.Cwes)),
			},
		},
	}
	for i, cwe := range advisory.Cwes {
		pt.ProblemtypeData[0].Description[i] = &dstschema.CVEJSON40LangString{
			Lang:  "en",
			Value: cwe,
		}
	}
	return pt
}

func newReferences(advisory *srcschema.SnykAdvisory) *dstschema.CVEJSON40References {
	if len(advisory.References) == 0 {
		return nil
	}
	nrefs := 1 + len(advisory.References) + len(advisory.Cves)
	refs := &dstschema.CVEJSON40References{
		ReferenceData: make([]*dstschema.CVEJSON40Reference, 0, nrefs),
	}
	addRef := func(name, url string) {
		refs.ReferenceData = append(refs.ReferenceData, &dstschema.CVEJSON40Reference{
			Name: name,
			URL:  url,
		})
	}
	if advisory.Title != "" && advisory.URL != "" {
		addRef(advisory.Title, advisory.URL)
	}
	for _, ref := range advisory.References {
		addRef(ref.Title, ref.URL)
	}
	for _, cve := range advisory.Cves {
		addRef(cve, "")
	}
	return refs
}

func newConfigurations(advisory *srcschema.SnykAdvisory) *dstschema.NVDCVEFeedJSON10DefConfigurations {
	nodes := []*dstschema.NVDCVEFeedJSON10DefNode{
		&dstschema.NVDCVEFeedJSON10DefNode{Operator: "OR"},
	}
	var err error
	var product string
	if product, err = wfn.WFNize(advisory.Package); err != nil {
		log.Printf("can't wfnize %q\n", advisory.Package)
		product = advisory.Package
	}
	cpe := wfn.Attributes{Part: "a", Product: product}
	cpe22URI := cpe.BindToURI()
	cpe23URI := cpe.BindToFmtString()
	for _, versions := range advisory.VulnerableVersions {
		vRanges, err := parseVersionRange(versions)
		if err != nil {
			log.Printf("could not generate configuration for item %s, vulnerable ver %q: %v", advisory.ID, versions, err)
			continue
		}
		for _, vRange := range vRanges {
			node := &dstschema.NVDCVEFeedJSON10DefCPEMatch{
				CPEName: []*dstschema.NVDCVEFeedJSON10DefCPEName{
					&dstschema.NVDCVEFeedJSON10DefCPEName{
						Cpe22Uri: cpe22URI,
						Cpe23Uri: cpe23URI,
					},
				},
				Cpe23Uri:              cpe23URI,
				VersionStartIncluding: vRange.minVerIncl,
				VersionStartExcluding: vRange.minVerExcl,
				VersionEndIncluding:   vRange.maxVerIncl,
				VersionEndExcluding:   vRange.maxVerExcl,
				Vulnerable:            true,
			}
			nodes[0].CPEMatch = append(nodes[0].CPEMatch, node)
		}
	}
	return &dstschema.NVDCVEFeedJSON10DefConfigurations{
		CVEDataVersion: cveVersion,
		Nodes:          nodes,
	}
}

func newImpact(advisory *srcschema.SnykAdvisory) *dstschema.NVDCVEFeedJSON10DefImpact {
	return &dstschema.NVDCVEFeedJSON10DefImpact{
		BaseMetricV3: &dstschema.NVDCVEFeedJSON10DefImpactBaseMetricV3{
			CVSSV3: &dstschema.CVSSV30{
				VectorString: advisory.CVSSV3,
				BaseScore:    advisory.CvssScore,
			},
		},
	}
}
