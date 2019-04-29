package converter

import (
	"log"

	dstSchema "github.com/facebookincubator/nvdtools/cvefeed/jsonschema"
	srcSchema "github.com/facebookincubator/nvdtools/providers/idefense/schema"

	"github.com/pkg/errors"
)

const (
	cveDataVersion = "4.0"
)

// Convert converts iDefense vulnerability to NVD format
func Convert(input <-chan *srcSchema.IDefenseVulnerability) *dstSchema.NVDCVEFeedJSON10 {
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

func convert(item *srcSchema.IDefenseVulnerability) (*dstSchema.NVDCVEFeedJSON10DefCVEItem, error) {
	lastModifiedDate, err := convertTime(item.LastModified)
	if err != nil {
		return nil, errors.Wrap(err, "can't convert last modified date")
	}
	publishedDate, err := convertTime(item.LastPublished)
	if err != nil {
		return nil, errors.Wrap(err, "can't convert published date")
	}

	configurations, err := makeConfigurations(item)
	if err != nil {
		return nil, errors.Wrap(err, "can't create configurations")
	}

	return &dstSchema.NVDCVEFeedJSON10DefCVEItem{
		CVE: &dstSchema.CVEJSON40{
			CVEDataMeta: &dstSchema.CVEJSON40CVEDataMeta{
				ID:       makeID(item),
				ASSIGNER: "idefense",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: cveDataVersion,
			Description: &dstSchema.CVEJSON40Description{
				DescriptionData: []*dstSchema.CVEJSON40LangString{
					{Lang: "en", Value: item.Description},
				},
			},
			Problemtype: &dstSchema.CVEJSON40Problemtype{
				ProblemtypeData: []*dstSchema.CVEJSON40ProblemtypeProblemtypeData{
					{
						Description: []*dstSchema.CVEJSON40LangString{
							{Lang: "en", Value: item.Cwe},
						},
					},
				},
			},
			References: makeReferences(item),
		},
		Configurations: configurations,
		Impact: &dstSchema.NVDCVEFeedJSON10DefImpact{
			BaseMetricV2: &dstSchema.NVDCVEFeedJSON10DefImpactBaseMetricV2{
				CVSSV2: &dstSchema.CVSSV20{
					BaseScore:     item.Cvss2BaseScore,
					TemporalScore: item.Cvss2TemporalScore,
					VectorString:  item.Cvss2,
				},
			},
			BaseMetricV3: &dstSchema.NVDCVEFeedJSON10DefImpactBaseMetricV3{
				CVSSV3: &dstSchema.CVSSV30{
					BaseScore:     item.Cvss3BaseScore,
					TemporalScore: item.Cvss3TemporalScore,
					VectorString:  item.Cvss3,
				},
			},
		},
		LastModifiedDate: lastModifiedDate,
		PublishedDate:    publishedDate,
	}, nil
}

func makeID(item *srcSchema.IDefenseVulnerability) string {
	return "idefense-" + item.Key
}

func makeReferences(item *srcSchema.IDefenseVulnerability) *dstSchema.CVEJSON40References {
	if len(item.SourcesExternal) == 0 {
		return nil
	}

	var refsData []*dstSchema.CVEJSON40Reference
	addRef := func(name, url string) {
		refsData = append(refsData, &dstSchema.CVEJSON40Reference{
			Name: name,
			URL:  url,
		})
	}

	for _, source := range item.SourcesExternal {
		addRef(source.Name, source.URL)
	}
	if item.AlsoIdentifies != nil {
		for _, vuln := range item.AlsoIdentifies.Vulnerability {
			addRef(vuln.Key, "")
		}
	}
	for _, poc := range item.Pocs {
		addRef(poc.PocName, poc.URL)
	}
	for _, fix := range item.VendorFixExternal {
		addRef(fix.ID, fix.URL)
	}

	return &dstSchema.CVEJSON40References{
		ReferenceData: refsData,
	}
}

func makeConfigurations(item *srcSchema.IDefenseVulnerability) (*dstSchema.NVDCVEFeedJSON10DefConfigurations, error) {
	configs := findConfigurations(item)
	if len(configs) == 0 {
		return nil, errors.New("unable to find any configurations in data")
	}

	var matches []*dstSchema.NVDCVEFeedJSON10DefCPEMatch
	for _, cfg := range configs {
		for _, affected := range cfg.Affected {
			match := &dstSchema.NVDCVEFeedJSON10DefCPEMatch{
				Cpe23Uri:   cfg.Cpe23Uri,
				Vulnerable: true,
			}

			// determine version ranges
			if cfg.HasFixedBy {
				if affected.Prior {
					match.VersionEndExcluding = cfg.FixedByVersion
				} else {
					match.VersionStartIncluding = affected.Version
					match.VersionEndExcluding = cfg.FixedByVersion
				}
			} else {
				if affected.Prior {
					// affects all versions
				} else {
					match.VersionStartIncluding = affected.Version
				}
			}
			matches = append(matches, match)
		}
	}

	v := dstSchema.NVDCVEFeedJSON10DefConfigurations{
		CVEDataVersion: cveDataVersion,
		Nodes: []*dstSchema.NVDCVEFeedJSON10DefNode{
			&dstSchema.NVDCVEFeedJSON10DefNode{
				CPEMatch: matches,
				Operator: "OR",
			},
		},
	}

	return &v, nil
}
