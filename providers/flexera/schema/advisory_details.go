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

package schema

// https://app.quicktype.io?share=0hpDyoi4G7vzbKVRXzMB
// used file advisory_details.json
// then did manual fixing

// FlexeraAdvisory type
type FlexeraAdvisory struct {
	AdvisoryIdentifier        string                      `json:"advisory_identifier"`
	AggregateSeverity         string                      `json:"aggregate_severity"`
	Criticality               int64                       `json:"criticality"`
	CriticalityDescription    string                      `json:"criticality_description"`
	CveStrList                string                      `json:"cve_str_list"`
	Cvss3Info                 *FlexeraCvss3Info           `json:"cvss3_info"`
	CvssInfo                  *FlexeraCvssInfo            `json:"cvss_info"`
	Description               string                      `json:"description"`
	ID                        int64                       `json:"id"`
	Impact                    []*FlexeraImpact            `json:"impact"`
	IsZeroDay                 bool                        `json:"is_zero_day"`
	ModifiedDate              string                      `json:"modified_date"`
	Products                  []*FlexeraProduct           `json:"products"`
	References                []*FlexeraAdvisoryReference `json:"references"`
	Released                  string                      `json:"released"`
	Revisions                 []*FlexeraRevision          `json:"revisions"`
	Solution                  string                      `json:"solution"`
	SolutionStatus            int64                       `json:"solution_status"`
	SolutionStatusDescription string                      `json:"solution_status_description"`
	ThreatScore               string                      `json:"threat_score"`
	Title                     string                      `json:"title"`
	Type                      int64                       `json:"type"`
	Vulnerabilities           []*FlexeraVulnerability     `json:"vulnerabilities"`
}

// FlexeraCvss3Info type
type FlexeraCvss3Info struct {
	BaseScore    float64 `json:"cvss_base_score"`
	OverallScore float64 `json:"cvss_overall_score"`
	Vector       string  `json:"cvss_vector"`
}

// FlexeraCvssInfo type
type FlexeraCvssInfo struct {
	BaseScore    float64 `json:"cvss_base_score"`
	OverallScore float64 `json:"cvss_overall_score"`
	Vector       string  `json:"cvss_vector"`
}

// FlexeraImpact type
type FlexeraImpact struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// FlexeraProduct type
type FlexeraProduct struct {
	Cpes   []*FlexeraCpe `json:"cpes"`
	HasCpe bool          `json:"has_cpe"`
	ID     string        `json:"id"`
	IsOS   bool          `json:"is_os"`
	Name   string        `json:"name"`
}

// FlexeraCpe type
type FlexeraCpe struct {
	ModificationDate string `json:"modification_date"`
	Name             string `json:"name"`
	NvdID            string `json:"nvd_id"`
}

// FlexeraAdvisoryReference type
type FlexeraAdvisoryReference struct {
	Description  string `json:"description"`
	InternalType int64  `json:"internal_type"`
	Ordinal      int64  `json:"ordinal"`
	URL          string `json:"url"`
}

// FlexeraRevision type
type FlexeraRevision struct {
	Description string `json:"description"`
	Number      string `json:"number"`
	ReleaseDate string `json:"release_date"`
}

// FlexeraVulnerability type
type FlexeraVulnerability struct {
	Cve         string                       `json:"cve"`
	CveInfo     *FlexeraVulnerabilityCveInfo `json:"cve_info"`
	Description string                       `json:"description"`
	Ordinal     int64                        `json:"ordinal"`
	Products    []*FlexeraProduct            `json:"products"`
	Title       string                       `json:"title"`
}

// FlexeraVulnerabilityCveInfo type
type FlexeraVulnerabilityCveInfo struct {
	Cvss3Score  string              `json:"cvss3_score"`
	Cvss3Vector string              `json:"cvss3_vector"`
	CvssScore   string              `json:"cvss_score"`
	CvssVector  string              `json:"cvss_vector"`
	Description string              `json:"description"`
	Disclaimer  string              `json:"disclaimer"`
	OptName     string              `json:"opt_name"`
	OptType     string              `json:"opt_type"`
	Reference   string              `json:"reference"`
	References  []*CveInfoReference `json:"references"`
	Source      string              `json:"source"`
	ThreatScore float64             `json:"threat_score"`
	ThreatRules map[string]string   `json:"threat_rules"`
	UpdateFlag  int64               `json:"update_flag"`
}

// CveInfoReference type
type CveInfoReference struct {
	Source string `json:"source"`
	URL    string `json:"url"`
}
