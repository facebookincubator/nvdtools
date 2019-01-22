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

package cvefeed

import (
	"encoding/xml"
	"fmt"
	"testing"

	"github.com/jokLiu/nvdtools/cvefeed/internal/nvdxml"
	"github.com/jokLiu/nvdtools/wfn"
)

func TestMatchXML(t *testing.T) {
	cases := []struct {
		Inventory []*wfn.Attributes
		Dict      string
		Matches   []*wfn.Attributes
		Expect    bool
	}{
		{
			Inventory: []*wfn.Attributes{},
			Dict: `
				<vuln:vulnerable-configuration id="http://nvd.nist.gov/">
					<cpe-lang:logical-test operator="AND" negate="false">
					  <cpe-lang:logical-test operator="OR" negate="false">
					    <cpe-lang:fact-ref name="cpe:/a:microsoft:ie:6.%01"/>
					  </cpe-lang:logical-test>
					  <cpe-lang:logical-test operator="OR" negate="false">
					    <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_xp::sp%02"/>
					  </cpe-lang:logical-test>
					</cpe-lang:logical-test>
				</vuln:vulnerable-configuration>`,
			Expect: false,
		},
		{
			Inventory: []*wfn.Attributes{
				{Part: "o", Vendor: "linux", Product: "linux_kernel", Version: "2\\.6\\.1"},
				{Part: "a", Vendor: "djvulibre_project", Product: "djvulibre", Version: "3\\.5\\.11"},
			},
			Dict: `
				<vuln:vulnerable-configuration id="http://nvd.nist.gov/">
					<cpe-lang:logical-test operator="AND" negate="false">
					  <cpe-lang:logical-test operator="OR" negate="false">
					    <cpe-lang:fact-ref name="cpe:/a:microsoft:ie:6.%01"/>
					  </cpe-lang:logical-test>
					  <cpe-lang:logical-test operator="OR" negate="false">
					    <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_xp::sp%02"/>
					  </cpe-lang:logical-test>
					</cpe-lang:logical-test>
				</vuln:vulnerable-configuration>`,
			Expect: false,
		},
		{
			Inventory: []*wfn.Attributes{
				{Part: "o", Vendor: "microsoft", Product: "windows_xp", Update: "sp3"},
				{Part: "a", Vendor: "microsoft", Product: "ie", Version: "6\\.0"},
				{Part: "a", Vendor: "facebook", Product: "styx", Version: "0\\.1"},
			},
			Dict: `
				<vuln:vulnerable-configuration id="http://nvd.nist.gov/">
					<cpe-lang:logical-test operator="AND" negate="false">
					  <cpe-lang:logical-test operator="OR" negate="false">
					    <cpe-lang:fact-ref name="cpe:/a:microsoft:ie:6.%01"/>
					  </cpe-lang:logical-test>
					  <cpe-lang:logical-test operator="OR" negate="false">
					    <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_xp::sp%02"/>
					  </cpe-lang:logical-test>
					</cpe-lang:logical-test>
				</vuln:vulnerable-configuration>`,
			Matches: []*wfn.Attributes{
				{Part: "o", Vendor: "microsoft", Product: "windows_xp", Update: "sp3"},
				{Part: "a", Vendor: "microsoft", Product: "ie", Version: "6\\.0"},
			},
			Expect: true,
		},
		{
			Inventory: []*wfn.Attributes{
				{Part: "h", Vendor: wfn.NA, Product: wfn.NA},
				{Part: "o", Vendor: wfn.NA, Product: wfn.NA},
				{Part: "a", Vendor: wfn.Any, Product: "geoip", Version: "1\\.5\\.0"},
			},
			Dict: `
		    <vuln:vulnerable-configuration id="http://nvd.nist.gov/">
		      <cpe-lang:logical-test operator="AND" negate="false">
		        <cpe-lang:logical-test operator="OR" negate="false">
		          <cpe-lang:fact-ref name="cpe:/a:microsoft:internet_explorer:11"/>
		        </cpe-lang:logical-test>
		        <cpe-lang:logical-test operator="OR" negate="true">
		          <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_10"/>
		        </cpe-lang:logical-test>
		      </cpe-lang:logical-test>
		    </vuln:vulnerable-configuration>
		    <vuln:vulnerable-configuration id="http://nvd.nist.gov/">
		      <cpe-lang:logical-test operator="OR" negate="false">
		        <cpe-lang:fact-ref name="cpe:/a:microsoft:internet_explorer:10"/>
		      </cpe-lang:logical-test>
		    </vuln:vulnerable-configuration>`,
			Expect: false,
		},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			var dict nvdxml.PlatformSpecificationType
			if err := xml.Unmarshal([]byte(c.Dict), &dict); err != nil {
				t.Fatalf("failed to unmarshal test case dictionary: %v", err)
			}
			nvdxml.ReparsePlatformSpecification(&dict)
			mm, ok := Match(c.Inventory, []LogicalTest{LogicalTest(&dict)}, false)
			if ok != c.Expect {
				t.Fatalf("expected %t, got %t", c.Expect, ok)
			}
			if ok && !matchesAll(mm, c.Matches) {
				t.Fatalf("wrong match: expected %v, got %v", c.Matches, mm)
			}
		})
	}
}

func TestMatchXMLRequireVersion(t *testing.T) {
	benchDict := `
<vuln:vulnerable-configuration id="http://nvd.nist.gov/">
 <cpe-lang:logical-test operator="OR" negate="false">
   <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_xp"/>
 </cpe-lang:logical-test>
</vuln:vulnerable-configuration>
`
	inventory := []*wfn.Attributes{
		{Part: "o", Vendor: "microsoft", Product: "windows_xp", Update: "sp3"},
	}
	var dict nvdxml.PlatformSpecificationType
	if err := xml.Unmarshal([]byte(benchDict), &dict); err != nil {
		t.Fatalf("failed to unmarshal test case dictionary: %v", err)
	}
	nvdxml.ReparsePlatformSpecification(&dict)
	if _, ok := Match(inventory, []LogicalTest{LogicalTest(&dict)}, true); ok {
		t.Fatal("platform was expected to be ignored because of absence of version, but matched")
	}
}

func BenchmarkMatchXMLAny(b *testing.B) {
	benchDict := `
<vuln:vulnerable-configuration id="http://nvd.nist.gov/">
	<cpe-lang:logical-test operator="AND" negate="false">
	  <cpe-lang:logical-test operator="OR" negate="false">
	    <cpe-lang:fact-ref name="cpe:/a"/>
	  </cpe-lang:logical-test>
	  <cpe-lang:logical-test operator="OR" negate="false">
	    <cpe-lang:fact-ref name="cpe:/o"/>
	  </cpe-lang:logical-test>
	</cpe-lang:logical-test>
</vuln:vulnerable-configuration>
`
	inventory := []*wfn.Attributes{
		{Part: "o", Vendor: "microsoft", Product: "windows_xp", Update: "sp3"},
		{Part: "a", Vendor: "microsoft", Product: "ie", Version: "6\\.0"},
	}
	var dict nvdxml.PlatformSpecificationType
	if err := xml.Unmarshal([]byte(benchDict), &dict); err != nil {
		b.Fatalf("failed to unmarshal test case dictionary: %v", err)
	}
	nvdxml.ReparsePlatformSpecification(&dict)
	for i := 0; i < b.N; i++ {
		if _, ok := Match(inventory, []LogicalTest{LogicalTest(&dict)}, false); !ok {
			b.Fatal("expected case to match, but it didn't")
		}
	}
}

func BenchmarkMatchXMLExact(b *testing.B) {
	benchDict := `
<vuln:vulnerable-configuration id="http://nvd.nist.gov/">
	<cpe-lang:logical-test operator="AND" negate="false">
	  <cpe-lang:logical-test operator="OR" negate="false">
	    <cpe-lang:fact-ref name="cpe:/a:microsoft:ie:6.0"/>
	  </cpe-lang:logical-test>
	  <cpe-lang:logical-test operator="OR" negate="false">
	    <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_xp::sp3"/>
	  </cpe-lang:logical-test>
	</cpe-lang:logical-test>
</vuln:vulnerable-configuration>
`
	inventory := []*wfn.Attributes{
		{Part: "o", Vendor: "microsoft", Product: "windows_xp", Update: "sp3"},
		{Part: "a", Vendor: "microsoft", Product: "ie", Version: "6\\.0"},
	}
	var dict nvdxml.PlatformSpecificationType
	if err := xml.Unmarshal([]byte(benchDict), &dict); err != nil {
		b.Fatalf("failed to unmarshal test case dictionary: %v", err)
	}
	nvdxml.ReparsePlatformSpecification(&dict)
	for i := 0; i < b.N; i++ {
		if _, ok := Match(inventory, []LogicalTest{LogicalTest(&dict)}, false); !ok {
			b.Fatal("expected case to match, but it didn't")
		}
	}
}

func BenchmarkMatchXMLShortcuts(b *testing.B) {
	benchDict := `
<vuln:vulnerable-configuration id="http://nvd.nist.gov/">
	<cpe-lang:logical-test operator="AND" negate="false">
	  <cpe-lang:logical-test operator="OR" negate="false">
 	    <cpe-lang:fact-ref name="cpe:/a:%02soft:%02ie%02:6.%01"/>
	  </cpe-lang:logical-test>
	  <cpe-lang:logical-test operator="OR" negate="false">
    	<cpe-lang:fact-ref name="cpe:/o:%02icro%02:windows%02::sp%01"/>
	  </cpe-lang:logical-test>
	</cpe-lang:logical-test>
</vuln:vulnerable-configuration>
`
	inventory := []*wfn.Attributes{
		{Part: "o", Vendor: "microsoft", Product: "windows_xp", Update: "sp3"},
		{Part: "a", Vendor: "microsoft", Product: "ie", Version: "6\\.0"},
	}
	var dict nvdxml.PlatformSpecificationType
	if err := xml.Unmarshal([]byte(benchDict), &dict); err != nil {
		b.Fatalf("failed to unmarshal test case dictionary: %v", err)
	}
	nvdxml.ReparsePlatformSpecification(&dict)
	for i := 0; i < b.N; i++ {
		if _, ok := Match(inventory, []LogicalTest{LogicalTest(&dict)}, false); !ok {
			b.Fatal("expected case to match, but it didn't")
		}
	}
}

func matchesAll(src, tgt []*wfn.Attributes) bool {
	if len(src) != len(tgt) {
		return false
	}
	for i, j := 0, 0; i < len(src); i, j = i+1, 0 {
		for ; j < len(tgt); j++ {
			if *src[i] == *tgt[j] {
				break
			}
		}
		if j == len(tgt) { // reached the end, no match
			return false
		}
	}
	return true
}
