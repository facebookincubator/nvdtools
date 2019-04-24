// Package rustsec provides a converter for rustsec advisories to nvd.
package rustsec

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/facebookincubator/nvdtools/cvefeed/nvdcommon"
	"github.com/facebookincubator/nvdtools/cvefeed/nvdjson"
	"github.com/facebookincubator/nvdtools/wfn"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
)

// Convert scans a directory recursively for rustsec advisory files and convert to NVD CVE JSON 1.0 format.
func Convert(dir string) (*nvdjson.NVDCVEFeedJSON10, error) {
	feed := &nvdjson.NVDCVEFeedJSON10{}

	walker := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		_, fn := filepath.Split(path)
		if !(strings.HasPrefix(fn, "RUSTSEC") && strings.HasSuffix(fn, ".toml")) {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		cve, err := ConvertAdvisory(f)
		if err != nil {
			return errors.Wrapf(err, "error parsing file: %s", path)
		}
		feed.CVEItems = append(feed.CVEItems, cve)
		return nil
	}

	err := filepath.Walk(dir, walker)
	if err != nil {
		return nil, err
	}

	return feed, nil
}

// ConvertAdvisory converts the rustsec toml advisory data from r to NVD CVE JSON 1.0 format.
func ConvertAdvisory(r io.Reader) (*nvdjson.NVDCVEFeedJSON10DefCVEItem, error) {
	var spec advisoryFile
	_, err := toml.DecodeReader(r, &spec)
	if err != nil {
		return nil, errors.Wrap(err, "cannot decode rustsec toml advisory")
	}

	return spec.Item.Convert()
}

// advisoryFile is the toml spec for rustsec advisories.
// Ref: https://github.com/RustSec/advisory-db
type advisoryFile struct {
	Item advisoryItem `toml:"advisory"`
}

type advisoryItem struct {
	ID                 string   `toml:"id"`
	Package            string   `toml:"package"`
	Date               string   `toml:"date"`
	Title              string   `toml:"title"`
	Description        string   `toml:"description"`
	URL                string   `toml:"url"`
	Aliases            []string `toml:"aliases"`
	Keywords           []string `toml:"keywords"`
	References         []string `toml:"references"`
	PatchedVersions    []string `toml:"patched_versions"`
	AffectedArch       []string `toml:"affected_arch"`
	AffectedOS         []string `toml:"affected_os"`
	AffectedFunctions  []string `toml:"affected_functions"`
	UnaffectedVersions []string `toml:"unaffected_versions"`
}

const advisoryTimeLayout = "2006-01-02"

func (item *advisoryItem) Convert() (*nvdjson.NVDCVEFeedJSON10DefCVEItem, error) {
	// TODO: Add CVSS score: https://github.com/RustSec/advisory-db/issues/20

	t, err := time.Parse(advisoryTimeLayout, item.Date)
	if err != nil {
		return nil, errors.Wrapf(err, "malformed date layout in %#v: %q", item, item.Date)
	}

	conf, err := item.newConfigurations()
	if err != nil {
		return nil, err
	}

	cve := &nvdjson.NVDCVEFeedJSON10DefCVEItem{
		CVE: &nvdjson.CVEJSON40{
			CVEDataMeta: &nvdjson.CVEJSON40CVEDataMeta{
				ID:       item.ID,
				ASSIGNER: "RustSec",
			},
			DataFormat:  "MITRE",
			DataType:    "CVE",
			DataVersion: "4.0",
			Description: &nvdjson.CVEJSON40Description{
				DescriptionData: []*nvdjson.CVEJSON40LangString{
					{
						Lang:  "en",
						Value: item.Description,
					},
				},
			},
			References: item.newReferences(),
		},
		Configurations:   conf,
		LastModifiedDate: t.Format(nvdcommon.TimeLayout),
		PublishedDate:    t.Format(nvdcommon.TimeLayout),
	}

	return cve, nil
}

func (item *advisoryItem) newReferences() *nvdjson.CVEJSON40References {
	if len(item.References) == 0 {
		return nil
	}

	nrefs := 1 + len(item.Aliases) + len(item.References)
	refs := &nvdjson.CVEJSON40References{
		ReferenceData: make([]*nvdjson.CVEJSON40Reference, 0, nrefs),
	}

	addRef := func(name, url string) {
		refs.ReferenceData = append(refs.ReferenceData, &nvdjson.CVEJSON40Reference{
			Name: name,
			URL:  url,
		})
	}

	if item.Title != "" || item.URL != "" {
		addRef(item.Title, item.URL)
	}

	for _, ref := range item.Aliases {
		addRef(ref, "")
	}

	for _, ref := range item.References {
		addRef(ref, "")
	}

	rd := refs.ReferenceData
	sort.Slice(rd, func(i, j int) bool {
		return strings.Compare(rd[i].Name, rd[j].Name) < 0
	})

	return refs
}

func (item *advisoryItem) newConfigurations() (*nvdjson.NVDCVEFeedJSON10DefConfigurations, error) {
	pkg, err := wfn.WFNize(item.Package)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot wfn-ize: %q", item.Package)
	}
	cpe := wfn.Attributes{Part: "a", Product: pkg}
	cpe22uri := cpe.BindToURI()
	cpe23uri := cpe.BindToFmtString()

	matches := []*nvdjson.NVDCVEFeedJSON10DefCPEMatch{}
	unnafected := append(item.UnaffectedVersions, item.PatchedVersions...)

	for _, version := range unnafected {
		if len(version) < 2 {
			return nil, errors.Errorf("malformed version schema in %#v: %q", item, version)
		}

		var curver string

		switch version[:1] {
		case "=", "^":
			curver = strings.TrimSpace(version[1:])
			wfnver, err := wfn.WFNize(curver)
			if err != nil {
				return nil, errors.Wrapf(err, "cannot wfn-ize version: %q", curver)
			}
			cpe := wfn.Attributes{Part: "a", Product: pkg, Version: wfnver}
			cpe22uri := cpe.BindToURI()
			cpe23uri := cpe.BindToFmtString()
			match := &nvdjson.NVDCVEFeedJSON10DefCPEMatch{
				CPEName: []*nvdjson.NVDCVEFeedJSON10DefCPEName{
					{
						Cpe22Uri: cpe22uri,
						Cpe23Uri: cpe23uri,
					},
				},
				Cpe23Uri:   cpe23uri,
				Vulnerable: version[:1] == "=",
			}
			matches = append(matches, match)

		case ">", "<":
			match := &nvdjson.NVDCVEFeedJSON10DefCPEMatch{
				CPEName: []*nvdjson.NVDCVEFeedJSON10DefCPEName{
					{
						Cpe22Uri: cpe22uri,
						Cpe23Uri: cpe23uri,
					},
				},
				Cpe23Uri:   cpe23uri,
				Vulnerable: false, // these are patched + unaffected versions
			}
			curver = strings.TrimSpace(version[2:])
			switch version[:2] {
			case "> ":
				match.VersionStartExcluding = curver
			case ">=":
				match.VersionStartIncluding = curver
			case "< ":
				match.VersionEndExcluding = curver
			case "<=":
				match.VersionEndIncluding = curver
			default:
				return nil, errors.Errorf("malformed version schema in %#v: %q", item, version)
			}
			matches = append(matches, match)

		default:
			return nil, errors.Errorf("malformed version schema in %#v: %q", item, version)
		}
	}

	conf := &nvdjson.NVDCVEFeedJSON10DefConfigurations{
		CVEDataVersion: "4.0",
		Nodes: []*nvdjson.NVDCVEFeedJSON10DefNode{
			{
				Operator: "AND",
				Children: []*nvdjson.NVDCVEFeedJSON10DefNode{
					{
						CPEMatch: []*nvdjson.NVDCVEFeedJSON10DefCPEMatch{
							{
								CPEName: []*nvdjson.NVDCVEFeedJSON10DefCPEName{
									{
										Cpe22Uri: cpe22uri,
										Cpe23Uri: cpe23uri,
									},
								},
								Cpe23Uri:              cpe23uri,
								Vulnerable:            false,
								VersionStartIncluding: "0",
							},
						},
					},
					{
						Negate:   true,
						CPEMatch: matches,
					},
				},
			},
		},
	}

	return conf, nil
}
