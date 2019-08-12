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

package wfn

// Matcher knows whether it matches some attributes
type Matcher interface {
	// Match returns whether attributes can be matches to it
	// if require version, then Matcher which matches all versions should return false
	Match(attrs *Attributes, requireVersion bool) bool
	// Attrs returns all attributes that are used by in the matching process
	Attrs() []*Attributes
}

// Matches returns all attributes which the given matcher matched
func Matches(m Matcher, attrss []*Attributes, requireVersion bool) (matches []*Attributes) {
	for _, attrs := range attrss {
		if m.Match(attrs, requireVersion) {
			matches = append(matches, attrs)
		}
	}
	return matches
}

// Attrs is part of the Matcher interface
func (a *Attributes) Attrs() []*Attributes {
	return []*Attributes{a}
}

// Match is part of the Matcher interface
func (a *Attributes) Match(attrs *Attributes, requireVersion bool) bool {
	if a == nil || attrs == nil {
		return a == attrs // both are nil
	}

	if requireVersion {
		if a.Version == Any {
			return false
		}
	}

	return a.MatchWithoutVersion(attrs) && a.MatchOnlyVersion(attrs)
}

func (a *Attributes) MatchOnlyVersion(attrs *Attributes) bool {
	if a == nil || attrs == nil {
		return a == attrs // both are nil
	}
	return matchAttr(a.Version, attrs.Version)
}

func (a *Attributes) MatchWithoutVersion(attrs *Attributes) bool {
	if a == nil || attrs == nil {
		return a == attrs // both are nil
	}
	return matchAttr(a.Product, attrs.Product) &&
		matchAttr(a.Vendor, attrs.Vendor) && matchAttr(a.Part, attrs.Part) &&
		matchAttr(a.Update, attrs.Update) && matchAttr(a.Edition, attrs.Edition) &&
		matchAttr(a.Language, attrs.Language) && matchAttr(a.SWEdition, attrs.SWEdition) &&
		matchAttr(a.TargetHW, attrs.TargetHW) && matchAttr(a.TargetSW, attrs.TargetSW) &&
		matchAttr(a.Other, attrs.Other)
}

// MatchAll returns a Matcher which matches only if all matchers match
func MatchAll(ms ...Matcher) Matcher {
	return andMatcher(ms)
}

// MatchAll returns a Matcher which matches if any of the matchers match
func MatchAny(ms ...Matcher) Matcher {
	return orMatcher(ms)
}

// DontMatch returns a Matcher which matches if the given matchers doesn't
func DontMatch(m Matcher) Matcher {
	return notMatcher{m}
}

type andMatcher []Matcher

// Match is part of the Matcher interface
func (am andMatcher) Match(attrs *Attributes, requireVersion bool) bool {
	for _, m := range am {
		if !m.Match(attrs, requireVersion) {
			return false
		}
	}
	return true
}

// Attrs is part of the Matcher interface
func (am andMatcher) Attrs() []*Attributes {
	return collectAttrs(am)
}

type orMatcher []Matcher

// Match is part of the Matcher interface
func (om orMatcher) Match(attrs *Attributes, requireVersion bool) bool {
	for _, m := range om {
		if m.Match(attrs, requireVersion) {
			return true
		}
	}
	return false
}

// Attrs is part of the Matcher interface
func (om orMatcher) Attrs() []*Attributes {
	return collectAttrs(om)
}

type notMatcher struct {
	Matcher
}

// Match is part of the Matcher interface
func (nm notMatcher) Match(attrs *Attributes, requireVersion bool) bool {
	return !nm.Matcher.Match(attrs, requireVersion)
}

func collectAttrs(mm []Matcher) []*Attributes {
	var attrs []*Attributes
	for _, m := range mm {
		attrs = append(attrs, m.Attrs()...)
	}
	return attrs
}
