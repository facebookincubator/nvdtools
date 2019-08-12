package cvefeed

import (
	"github.com/facebookincubator/nvdtools/wfn"
)

// Vuln is a vulnerability interface
type Vuln interface {
	// vulnerability should also be able to match attributes
	wfn.Matcher
	// ID returns the vulnerability ID
	ID() string
	// CVEs returns all CVEs it includes/references
	CVEs() []string
	// CWEs returns all CWEs for this vulnerability
	CWEs() []string
	// CVSSv2BaseScore returns CVSS v2 base score
	CVSSv2BaseScore() float64
	// CVSSv2BaseScore returns CVSS v2 vector
	CVSSv2Vector() string
	// CVSSv2BaseScore returns CVSS v3 base score
	CVSSv3BaseScore() float64
	// CVSSv2BaseScore returns CVSS v3 vector
	CVSSv3Vector() string
}

// MergeVuln combines two Vulns:
// resulted Vuln inherits all mutually exclusive methods (e.g. ID()) from Vuln x;
// functions returning CVEs and CWEs return distinct(union(x,y))
// the returned vuln matches attributes if x matches AND y doesn't
func MergeVulns(x, y Vuln) Vuln {
	cvssv2 := x.CVSSv2BaseScore()
	cvssv2Vec := x.CVSSv2Vector()
	if c := y.CVSSv2BaseScore(); c > cvssv2 {
		cvssv2 = c
		cvssv2Vec = y.CVSSv2Vector()
	}

	cvssv3 := x.CVSSv3BaseScore()
	cvssv3Vec := x.CVSSv3Vector()
	if c := y.CVSSv3BaseScore(); c > cvssv3 {
		cvssv3 = c
		cvssv3Vec = y.CVSSv3Vector()
	}

	return &vuln{
		id:        x.ID(),
		cves:      mergeUnique(x.CVEs, y.CVEs),
		cwes:      mergeUnique(x.CWEs, y.CWEs),
		cvssv2:    cvssv2,
		cvssv2Vec: cvssv2Vec,
		cvssv3:    cvssv3,
		cvssv3Vec: cvssv3Vec,
		Matcher:   wfn.MatchAll(x, wfn.DontMatch(y)),
	}
}

// vuln implements Vuln by storing all inside the struct
type vuln struct {
	id        string
	cves      []string
	cwes      []string
	cvssv2    float64
	cvssv2Vec string
	cvssv3    float64
	cvssv3Vec string
	wfn.Matcher
}

func (v *vuln) ID() string {
	return v.id
}

func (v *vuln) CVEs() []string {
	return v.cves
}

func (v *vuln) CWEs() []string {
	return v.cwes
}

func (v *vuln) CVSSv2BaseScore() float64 {
	return v.cvssv2
}

func (v *vuln) CVSSv2Vector() string {
	return v.cvssv2Vec
}

func (v *vuln) CVSSv3BaseScore() float64 {
	return v.cvssv3
}

func (v *vuln) CVSSv3Vector() string {
	return v.cvssv3Vec
}

func mergeUnique(gs ...func() []string) []string {
	var ss []string
	set := map[string]bool{}
	for _, g := range gs {
		for _, s := range g() {
			if !set[s] {
				ss = append(ss, s)
			}
			set[s] = true
		}
	}
	return ss
}
