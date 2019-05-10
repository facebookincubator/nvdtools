package jsonschema

// language -> [advisories]
type Snyk map[string][]*SnykAdvisory

type SnykAdvisory struct {
	CVSSV3             string           `json:"cvssV3"`
	CreationTime       string           `json:"creationTime"`
	Credit             []string         `json:"credit"`
	Cves               []string         `json:"cves"`
	CvssScore          float64          `json:"cvssScore"`
	Cwes               []string         `json:"cwes"`
	Description        string           `json:"description"`
	DisclosureTime     string           `json:"disclosureTime"`
	Exploit            string           `json:"exploit"`
	Fixable            bool             `json:"fixable"`
	HashesRange        []string         `json:"hashesRange,omitempty"`
	ID                 string           `json:"id"`
	Language           string           `json:"language"`
	ModificationTime   string           `json:"modificationTime"`
	Package            string           `json:"package"`
	PatchExists        bool             `json:"patchExists"`
	PublicationTime    string           `json:"publicationTime"`
	References         []*SnykReference `json:"references"`
	Severity           string           `json:"severity"`
	Title              string           `json:"title"`
	URL                string           `json:"url"`
	VulnerableHashes   []string         `json:"vulnerableHashes,omitempty"`
	VulnerableVersions []string         `json:"vulnerableVersions"`
}

type SnykReference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}
