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
