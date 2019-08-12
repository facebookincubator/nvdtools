package nvd

import (
	"regexp"

	"github.com/facebookincubator/nvdtools/wfn"
)

var cveRegex = regexp.MustCompile("CVE-[0-9]{4}-[0-9]{4,}")

func (cve *NVDCVEFeedJSON10DefCVEItem) Vuln() *nvdVuln {
	var ms []wfn.Matcher
	for _, node := range cve.Configurations.Nodes {
		if node != nil {
			if m := node.Matcher(); m != nil {
				ms = append(ms, m)
			}
		}
	}

	return &nvdVuln{
		cveItem: cve,
		Matcher: wfn.MatchAny(ms...),
	}
}

// nvdVuln implements the cvefeed.Vuln interface
type nvdVuln struct {
	cveItem *NVDCVEFeedJSON10DefCVEItem
	wfn.Matcher
}

// ID is a part of the cvefeed.Vuln Interface
func (v *nvdVuln) ID() string {
	if v == nil || v.cveItem == nil || v.cveItem.CVE == nil || v.cveItem.CVE.CVEDataMeta == nil {
		return ""
	}
	return v.cveItem.CVE.CVEDataMeta.ID
}

// CVEs is a part of the cvefeed.Vuln Interface
func (v *nvdVuln) CVEs() []string {
	if v == nil || v.cveItem == nil || v.cveItem.CVE == nil {
		return nil
	}

	var cves []string

	addMatch := func(s string) bool {
		if cve := cveRegex.FindString(s); cve != "" {
			cves = append(cves, cve)
			return true
		}
		return false
	}

	// check if ID contains CVE
	addMatch(v.ID())

	// add references
	if refs := v.cveItem.CVE.References; refs != nil {
		for _, refd := range refs.ReferenceData {
			if refd != nil {
				addMatch(refd.Name)
			}
		}
	}

	return unique(cves)
}

// CWEs is a part of the cvefeed.Vuln Interface
func (v *nvdVuln) CWEs() []string {
	if v == nil || v.cveItem == nil || v.cveItem.CVE == nil || v.cveItem.CVE.Problemtype == nil {
		return nil
	}

	var cwes []string

	for _, ptd := range v.cveItem.CVE.Problemtype.ProblemtypeData {
		if ptd != nil {
			for _, desc := range ptd.Description {
				if desc != nil {
					if desc.Lang == "en" {
						cwes = append(cwes, desc.Value)
					}
				}
			}
		}
	}

	return unique(cwes)
}

// CVSSv2BaseScore is a part of the cvefeed.Vuln Interface
func (v *nvdVuln) CVSSv2BaseScore() float64 {
	if c := v.cvssv2(); c != nil {
		return c.BaseScore
	}
	return 0.0
}

// CVSSv2Vector is a part of the cvefeed.Vuln Interface
func (v *nvdVuln) CVSSv2Vector() string {
	if c := v.cvssv2(); c != nil {
		return c.VectorString
	}
	return ""
}

// CVSSv3BaseScore is a part of the cvefeed.Vuln Interface
func (v *nvdVuln) CVSSv3BaseScore() float64 {
	if c := v.cvssv3(); c != nil {
		return c.BaseScore
	}
	return 0.0
}

// CVSSv3Vector is a part of the cvefeed.Vuln Interface
func (v *nvdVuln) CVSSv3Vector() string {
	if c := v.cvssv3(); c != nil {
		return c.VectorString
	}
	return ""
}

// unique returns unique strings from input
func unique(ss []string) []string {
	var us []string
	set := make(map[string]bool)
	for _, s := range ss {
		if !set[s] {
			us = append(us, s)
		}
		set[s] = true
	}
	return us
}

// just a helper to return the cvssv2 data
func (v *nvdVuln) cvssv2() *CVSSV20 {
	if v == nil || v.cveItem == nil || v.cveItem.Impact == nil || v.cveItem.Impact.BaseMetricV2 == nil {
		return nil
	}
	return v.cveItem.Impact.BaseMetricV2.CVSSV2
}

// just a helper to return the cvssv3 data
func (v *nvdVuln) cvssv3() *CVSSV30 {
	if v == nil || v.cveItem == nil || v.cveItem.Impact == nil || v.cveItem.Impact.BaseMetricV3 == nil {
		return nil
	}
	return v.cveItem.Impact.BaseMetricV3.CVSSV3
}
