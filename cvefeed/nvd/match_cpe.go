package nvd

import (
	"fmt"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/facebookincubator/nvdtools/wfn"
)

// cpeMatch is a wrapper around the actual NVDCVEFeedJSON10DefCPEMatch
type cpeMatch struct {
	*wfn.Attributes
	versionEndExcluding   string
	versionEndIncluding   string
	versionStartExcluding string
	versionStartIncluding string
	hasVersionRanges      bool
}

// Matcher returns an object which knows how to match attributes
func cpeMatcher(nvdMatch *schema.NVDCVEFeedJSON10DefCPEMatch) (wfn.Matcher, error) {
	parse := func(uri string) (*wfn.Attributes, error) {
		if uri == "" {
			return nil, fmt.Errorf("can't parse empty uri")
		}
		return wfn.Parse(uri)
	}

	// parse
	var match cpeMatch
	var err error
	if match.Attributes, err = parse(nvdMatch.Cpe23Uri); err != nil {
		if match.Attributes, err = parse(nvdMatch.Cpe22Uri); err != nil {
			return nil, fmt.Errorf("unable to parse both cpe2.2 and cpe2.3")
		}
	}

	match.versionEndExcluding = nvdMatch.VersionEndExcluding
	match.versionEndIncluding = nvdMatch.VersionEndIncluding
	match.versionStartExcluding = nvdMatch.VersionStartExcluding
	match.versionStartIncluding = nvdMatch.VersionStartIncluding

	if match.versionStartIncluding != "" || match.versionStartExcluding != "" ||
		match.versionEndIncluding != "" || match.versionEndExcluding != "" {
		match.hasVersionRanges = true
	}

	return &match, nil
}

// Match implements wfn.Matcher interface
func (match *cpeMatch) Match(attrs *wfn.Attributes, requireVersion bool) bool {
	if match == nil || match.Attributes == nil {
		return false
	}

	if requireVersion {
		// if we require version, then we need either version ranges or version not to be *
		if !match.hasVersionRanges && match.Attributes.Version == wfn.Any {
			return false
		}
	}

	// here we have a version: either actual one or ranges

	// check whether everything except for version matches
	if !match.Attributes.MatchWithoutVersion(attrs) {
		return false
	}

	// check whether version matches
	if match.Attributes.MatchOnlyVersion(attrs) {
		return true
	}

	// if it got to here, it means:
	//	- matched attrs without version

	// match version to ranges
	ver := wfn.StripSlashes(attrs.Version)

	switch {
	case match.versionStartIncluding != "" && smartVerCmp(ver, match.versionStartIncluding) >= 0:
		return true
	case match.versionStartExcluding != "" && smartVerCmp(ver, match.versionStartExcluding) > 0:
		return true
	case match.versionEndIncluding != "" && smartVerCmp(ver, match.versionEndIncluding) <= 0:
		return true
	case match.versionEndExcluding != "" && smartVerCmp(ver, match.versionEndExcluding) < 0:
		return true
	}

	return false
}
