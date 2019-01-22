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

package nvdxml

import (
	"github.com/jokLiu/nvdtools/cvefeed/internal/iface"
	"github.com/jokLiu/nvdtools/wfn"
)

// CVEID implements part of cvefeed.CVEItem interface
func (e *Entry) CVEID() string {
	return e.ID
}

// Config implemens part of cvefeed.CVEItem interface
func (e *Entry) Config() []iface.LogicalTest {
	return e.ifaceConfig
}

// PlatformSpecificationType is a cvefeed.LogicalTest

// LogicalOperator implements part of cvefeed.LogicalTest interface
func (ps *PlatformSpecificationType) LogicalOperator() string {
	switch {
	case ps.PlatformConfiguration != nil:
		return ps.PlatformConfiguration.LogicalTest.LogicalOperator()
	case ps.LogicalTest != nil:
		return ps.LogicalTest.LogicalOperator()
	default:
		return "eq"
	}
}

// NegateIfNeeded implements cvefeed.LogicalTest interface
func (ps *PlatformSpecificationType) NegateIfNeeded(b bool) bool {
	switch {
	case ps.PlatformConfiguration != nil:
		return ps.PlatformConfiguration.LogicalTest.NegateIfNeeded(b)
	case ps.LogicalTest != nil:
		return ps.LogicalTest.NegateIfNeeded(b)
	}
	return false
}

// InnerTests implements cvefeed.LogicalTest interface
func (ps *PlatformSpecificationType) InnerTests() []iface.LogicalTest {
	if ps.LogicalTest != nil {
		return ps.LogicalTest.ifaceLogicalTests
	}
	return nil
}

// CPEs implements cvefeed.LogicalTest interface
func (ps *PlatformSpecificationType) CPEs() []*wfn.Attributes {
	if ps.LogicalTest != nil {
		return ps.LogicalTest.CPEs()
	}
	return nil
}

// MatchPlatform implements part of cvefeed.LogicalTest interface
func (ps *PlatformSpecificationType) MatchPlatform(platform *wfn.Attributes, requireVersion bool) bool {
	for _, cpe := range ps.CPEs() {
		if requireVersion && cpe.Version == wfn.Any {
			continue
		}
		if wfn.Match(cpe, platform) {
			return true
		}
	}
	return false
}

// PlatformBaseType also is a cvefeed.LogicalTest

// LogicalOperator implements part of cvefeed.LogicalTest interface
func (pb *PlatformBaseType) LogicalOperator() string {
	if pb.LogicalTest != nil {
		return pb.LogicalTest.LogicalOperator()
	}
	return ""
}

// NegateIfNeeded implements cvefeed.LogicalTest interface
func (pb *PlatformBaseType) NegateIfNeeded(b bool) bool {
	if pb.LogicalTest != nil {
		return pb.LogicalTest.NegateIfNeeded(b)
	}
	return false
}

// InnerTests implements cvefeed.LogicalTest interface
func (pb *PlatformBaseType) InnerTests() []iface.LogicalTest {
	if pb.LogicalTest != nil {
		return pb.LogicalTest.ifaceLogicalTests
	}
	return nil
}

// CPEs implements cvefeed.LogicalTest interface
func (pb *PlatformBaseType) CPEs() []*wfn.Attributes {
	if pb.LogicalTest != nil {
		return pb.LogicalTest.CPEs()
	}
	return nil
}

// MatchPlatform implements part of cvefeed.LogicalTest interface
func (pb *PlatformBaseType) MatchPlatform(platform *wfn.Attributes, requireVersion bool) bool {
	for _, cpe := range pb.CPEs() {
		if requireVersion && cpe.Version == wfn.Any {
			continue
		}
		if wfn.Match(cpe, platform) {
			return true
		}
	}
	return false
}

// And finally, LogicalTestType is an cvefeed.LogicalTest, which at least makes sense

// LogicalOperator implements part of cvefeed.LogicalTest interface
func (lt *LogicalTestType) LogicalOperator() string {
	return string(lt.Op)
}

// NegateIfNeeded implements cvefeed.LogicalOperator interface
func (lt *LogicalTestType) NegateIfNeeded(b bool) bool {
	if lt.Neg {
		return !b
	}
	return b
}

// InnerTests implements cvefeed.LogicalTest interface
func (lt *LogicalTestType) InnerTests() []iface.LogicalTest {
	return lt.ifaceLogicalTests
}

// CPEs implements cvefeed.LogicalTest interface
func (lt *LogicalTestType) CPEs() []*wfn.Attributes {
	return collectCPEs(lt.FactRefs)
}

// MatchPlatform implements part of cvefeed.LogicalTest interface
func (lt *LogicalTestType) MatchPlatform(platform *wfn.Attributes, requireVersion bool) bool {
	for _, cpe := range lt.CPEs() {
		if requireVersion && cpe.Version == wfn.Any {
			continue
		}
		if wfn.Match(cpe, platform) {
			return true
		}
	}
	return false
}

func collectCPEs(factRefs []*FactRefType) []*wfn.Attributes {
	if len(factRefs) == 0 {
		return nil
	}
	cpes := make([]*wfn.Attributes, len(factRefs))
	for i, fr := range factRefs {
		cpes[i] = (*wfn.Attributes)(&fr.Name)
	}
	return cpes
}

// Reparse transforms set of structure parsed from XML vulnerability feed into compartible set of interfaces
func Reparse(xmlEntries []*Entry) []iface.CVEItem {
	entries := make([]iface.CVEItem, len(xmlEntries))
	for i, xe := range xmlEntries {
		xe.ifaceConfig = ReparsePlatformSpecifications(xe.Configuration)
		entries[i] = iface.CVEItem(xe)
	}
	return entries
}

// ReparsePlatformSpecifications transfoms slice of *PlatformSpecificationType to slice of LogicalTest interfaces.
// Processes the fields of PlatformSpecificationType structure recursively, doing necessary transformations.
func ReparsePlatformSpecifications(pss []*PlatformSpecificationType) []iface.LogicalTest {
	if len(pss) == 0 {
		return nil
	}
	lts := make([]iface.LogicalTest, len(pss))
	for i, ps := range pss {
		ReparsePlatformSpecification(ps)
		lts[i] = iface.LogicalTest(ps)
	}
	return lts
}

// ReparsePlatformSpecification ensures that children interface holders of the structure are populated with corresponding interfaces.
func ReparsePlatformSpecification(ps *PlatformSpecificationType) {
	if ps.PlatformConfiguration != nil && ps.PlatformConfiguration.LogicalTest != nil {
		ReparseLogicalTest(ps.PlatformConfiguration.LogicalTest)
	}
	if ps.LogicalTest != nil {
		ReparseLogicalTest(ps.LogicalTest)
	}
}

// ReparseLogicalTest populates internal slice of LogicalTest interfaces with typecasted children LogicalTest fields.
func ReparseLogicalTest(lt *LogicalTestType) {
	if len(lt.LogicalTests) == 0 {
		return
	}
	lt.ifaceLogicalTests = make([]iface.LogicalTest, len(lt.LogicalTests))
	for i, t := range lt.LogicalTests {
		ReparseLogicalTest(t)
		lt.ifaceLogicalTests[i] = iface.LogicalTest(t)
	}
}
