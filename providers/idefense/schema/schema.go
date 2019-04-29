// Code generated by `go generate`, do not edit

package schema

// IDefenseVulnerabilitySearchResults struct
type IDefenseVulnerabilitySearchResults struct {
	More      bool                     `json:"more"`
	Page      int                      `json:"page"`
	PageSize  int                      `json:"page_size"`
	Results   []*IDefenseVulnerability `json:"results"`
	TotalSize int                      `json:"total_size"`
}

// IDefenseVulnerability struct
type IDefenseVulnerability struct {
	AdvertisedBy                      *IDefenseVulnerabilityAdvertisedBy     `json:"advertised_by"`
	Affects                           *IDefenseVulnerabilityAffects          `json:"affects"`
	Alias                             []string                               `json:"alias"`
	AlsoIdentifies                    *IDefenseVulnerabilityAlsoIdentifies   `json:"also_identifies"`
	Analysis                          string                                 `json:"analysis"`
	ClassificationOfVulnerabilityType string                                 `json:"classification_of_vulnerability_type"`
	CreatedOn                         string                                 `json:"created_on"`
	Cvss2                             string                                 `json:"cvss2"`
	Cvss2BaseScore                    float64                                `json:"cvss2_base_score"`
	Cvss2TemporalScore                float64                                `json:"cvss2_temporal_score"`
	Cvss3                             string                                 `json:"cvss3"`
	Cvss3BaseScore                    float64                                `json:"cvss3_base_score"`
	Cvss3TemporalScore                float64                                `json:"cvss3_temporal_score"`
	Cwe                               string                                 `json:"cwe"`
	Description                       string                                 `json:"description"`
	Exclusive                         bool                                   `json:"exclusive"`
	ExploitedBy                       *IDefenseVulnerabilityExploitedBy      `json:"exploited_by"`
	FirstSeenActive                   string                                 `json:"first_seen_active"`
	FixedBy                           *IDefenseVulnerabilityFixedBy          `json:"fixed_by"`
	History                           []*IDefenseVulnerabilityHistory        `json:"history"`
	IdentifiedBy                      *IDefenseVulnerabilityIdentifiedBy     `json:"identified_by"`
	IndexTimestamp                    string                                 `json:"index_timestamp"`
	Key                               string                                 `json:"key"`
	LastModified                      string                                 `json:"last_modified"`
	LastPublished                     string                                 `json:"last_published"`
	MentionedBy                       []string                               `json:"mentioned_by"`
	Mitigation                        string                                 `json:"mitigation"`
	NotableVuln                       bool                                   `json:"notable_vuln"`
	NotableZeroDay                    bool                                   `json:"notable_zero_day"`
	Pocs                              []*IDefenseVulnerabilityProofOfConcept `json:"pocs"`
	Popularity                        int                                    `json:"popularity"`
	ReplicationID                     int                                    `json:"replication_id"`
	Severity                          int                                    `json:"severity"`
	SourcesExternal                   []*IDefenseVulnerabilitySource         `json:"sources_external"`
	ThreatTypes                       []string                               `json:"threat_types"`
	Title                             string                                 `json:"title"`
	Translations                      *IDefenseVulnerabilityTranslations     `json:"translations"`
	TranslationsFr                    *IDefenseVulnerabilityTranslations     `json:"translations_fr"`
	TranslationsJa                    *IDefenseVulnerabilityTranslations     `json:"translations_ja"`
	UUID                              string                                 `json:"uuid"`
	VendorFixExternal                 []*IDefenseVulnerabilityVendorAdvisory `json:"vendor_fix_external"`
	Workarounds                       []*IDefenseVulnerabilityWorkaround     `json:"workarounds"`
	Wormable                          bool                                   `json:"wormable"`
	ZeroDay                           bool                                   `json:"zero_day"`
}

// IDefenseVulnerabilityAdvertisedBy struct
type IDefenseVulnerabilityAdvertisedBy struct {
	ThreatGroup []*IDefenseVulnerabilityAdvertisedThreatGroup `json:"threat_group"`
}

// IDefenseVulnerabilityAffects struct
type IDefenseVulnerabilityAffects struct {
	Packages  []*IDefenseVulnerabilityAffectedPackage  `json:"packages"`
	VulnTechs []*IDefenseVulnerabilityAffectedVulnTech `json:"vuln_techs"`
}

// IDefenseVulnerabilityAlsoIdentifies struct
type IDefenseVulnerabilityAlsoIdentifies struct {
	Vulnerability []*IDefenseVulnerabilityOtherVulnerability `json:"vulnerability"`
}

// IDefenseVulnerabilityExploitedBy struct
type IDefenseVulnerabilityExploitedBy struct {
	File          []string `json:"file"`
	MaliciousTool []string `json:"malicious_tool"`
	MalwareFamily []string `json:"malware_family"`
}

// IDefenseVulnerabilityFixedBy struct
type IDefenseVulnerabilityFixedBy struct {
	Packages  []*IDefenseVulnerabilityPatchedPackage  `json:"packages"`
	VulnTechs []*IDefenseVulnerabilityPatchedVulnTech `json:"vuln_techs"`
}

// IDefenseVulnerabilityHistory struct
type IDefenseVulnerabilityHistory struct {
	Comment           string   `json:"comment"`
	Timestamp         string   `json:"timestamp"`
	UpdatedProperties []string `json:"updated_properties"`
}

// IDefenseVulnerabilityIdentifiedBy struct
type IDefenseVulnerabilityIdentifiedBy struct {
	DetectionSignature []string `json:"detection_signature"`
}

// IDefenseVulnerabilityProofOfConcept struct
type IDefenseVulnerabilityProofOfConcept struct {
	Datetime    string `json:"datetime"`
	Description string `json:"description"`
	PocAuthor   string `json:"poc_author"`
	PocName     string `json:"poc_name"`
	URL         string `json:"url"`
}

// IDefenseVulnerabilitySource struct
type IDefenseVulnerabilitySource struct {
	Datetime    string `json:"datetime"`
	Description string `json:"description"`
	Name        string `json:"name"`
	Reputation  int    `json:"reputation"`
	URL         string `json:"url"`
}

// IDefenseVulnerabilityTranslations struct
type IDefenseVulnerabilityTranslations struct {
	Analysis            string                                     `json:"analysis"`
	Description         string                                     `json:"description"`
	LastModified        string                                     `json:"last_modified"`
	Mitigation          string                                     `json:"mitigation"`
	ReplicationID       int                                        `json:"replication_id"`
	Title               string                                     `json:"title"`
	TranslatedTimestamp string                                     `json:"translated_timestamp"`
	TranslationHistory  []*IDefenseVulnerabilityTranslationHistory `json:"translation_history"`
}

// IDefenseVulnerabilityVendorAdvisory struct
type IDefenseVulnerabilityVendorAdvisory struct {
	Datetime string `json:"datetime"`
	ID       string `json:"id"`
	URL      string `json:"url"`
}

// IDefenseVulnerabilityWorkaround struct
type IDefenseVulnerabilityWorkaround struct {
	Comment      string `json:"comment"`
	URLReference string `json:"url_reference"`
}

// IDefenseVulnerabilityAdvertisedThreatGroup struct
type IDefenseVulnerabilityAdvertisedThreatGroup struct {
	CreatedOn    string   `json:"created_on"`
	Key          string   `json:"key"`
	LastModified string   `json:"last_modified"`
	ThreatTypes  []string `json:"threat_types"`
	UUID         string   `json:"uuid"`
}

// IDefenseVulnerabilityAffectedPackage struct
type IDefenseVulnerabilityAffectedPackage struct {
	AndPriorVersions bool   `json:"and_prior_versions"`
	Architecture     string `json:"architecture"`
	CreatedOn        string `json:"created_on"`
	Key              string `json:"key"`
	LastModified     string `json:"last_modified"`
	PackageName      string `json:"package_name"`
	PackageSecurity  bool   `json:"package_security"`
	PackageType      string `json:"package_type"`
	PackageVersion   string `json:"package_version"`
	UUID             string `json:"uuid"`
}

// IDefenseVulnerabilityAffectedVulnTech struct
type IDefenseVulnerabilityAffectedVulnTech struct {
	Alias            []string `json:"alias"`
	AndPriorVersions bool     `json:"and_prior_versions"`
	Category         []string `json:"category"`
	CpeInDictionary  bool     `json:"cpe_in_dictionary"`
	CreatedOn        string   `json:"created_on"`
	Description      string   `json:"description"`
	DisplayName      string   `json:"display_name"`
	Edition          string   `json:"edition"`
	Key              string   `json:"key"`
	Language         string   `json:"language"`
	LastModified     string   `json:"last_modified"`
	Part             string   `json:"part"`
	Product          string   `json:"product"`
	Update           string   `json:"update"`
	UUID             string   `json:"uuid"`
	Vendor           string   `json:"vendor"`
	Version          string   `json:"version"`
}

// IDefenseVulnerabilityOtherVulnerability struct
type IDefenseVulnerabilityOtherVulnerability struct {
	CreatedOn    string   `json:"created_on"`
	Key          string   `json:"key"`
	LastModified string   `json:"last_modified"`
	ThreatTypes  []string `json:"threat_types"`
	UUID         string   `json:"uuid"`
}

// IDefenseVulnerabilityPatchedPackage struct
type IDefenseVulnerabilityPatchedPackage struct {
	Architecture    string                        `json:"architecture"`
	CreatedOn       string                        `json:"created_on"`
	Key             string                        `json:"key"`
	LastModified    string                        `json:"last_modified"`
	PackageName     string                        `json:"package_name"`
	PackageSecurity bool                          `json:"package_security"`
	PackageType     string                        `json:"package_type"`
	PackageVersion  string                        `json:"package_version"`
	Patches         []*IDefenseVulnerabilityPatch `json:"patches"`
	UUID            string                        `json:"uuid"`
}

// IDefenseVulnerabilityPatchedVulnTech struct
type IDefenseVulnerabilityPatchedVulnTech struct {
	Alias           []string                      `json:"alias"`
	Category        []string                      `json:"category"`
	CpeInDictionary bool                          `json:"cpe_in_dictionary"`
	CreatedOn       string                        `json:"created_on"`
	Description     string                        `json:"description"`
	DisplayName     string                        `json:"display_name"`
	Edition         string                        `json:"edition"`
	Key             string                        `json:"key"`
	Language        string                        `json:"language"`
	LastModified    string                        `json:"last_modified"`
	Part            string                        `json:"part"`
	Patches         []*IDefenseVulnerabilityPatch `json:"patches"`
	Product         string                        `json:"product"`
	Update          string                        `json:"update"`
	UUID            string                        `json:"uuid"`
	Vendor          string                        `json:"vendor"`
	Version         string                        `json:"version"`
}

// IDefenseVulnerabilityTranslationHistory struct
type IDefenseVulnerabilityTranslationHistory struct {
	Comment           string   `json:"comment"`
	Timestamp         string   `json:"timestamp"`
	UpdatedProperties []string `json:"updated_properties"`
}

// IDefenseVulnerabilityPatch struct
type IDefenseVulnerabilityPatch struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}
