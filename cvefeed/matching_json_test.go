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
	"bytes"
	"fmt"
	"testing"

	"github.com/jokLiu/nvdtools/wfn"
)

func TestMatchJSON(t *testing.T) {
	cases := []struct {
		Rule      int
		Inventory []*wfn.Attributes
		Matches   []*wfn.Attributes
		Expect    bool
	}{
		{
			Rule:      0,
			Inventory: []*wfn.Attributes{},
			Expect:    false,
		},
		{
			Inventory: []*wfn.Attributes{
				{Part: "o", Vendor: "linux", Product: "linux_kernel", Version: "2\\.6\\.1"},
				{Part: "a", Vendor: "djvulibre_project", Product: "djvulibre", Version: "3\\.5\\.11"},
			},
			Expect: false,
		},
		{
			Rule: 0,
			Inventory: []*wfn.Attributes{
				{Part: "o", Vendor: "microsoft", Product: "windows_xp", Update: "sp3"},
				{Part: "a", Vendor: "microsoft", Product: "ie", Version: "6\\.0"},
				{Part: "a", Vendor: "facebook", Product: "styx", Version: "0\\.1"},
			},
			Matches: []*wfn.Attributes{
				{Part: "o", Vendor: "microsoft", Product: "windows_xp", Update: "sp3"},
				{Part: "a", Vendor: "microsoft", Product: "ie", Version: "6\\.0"},
			},
			Expect: true,
		},
		{
			Rule: 1,
			Inventory: []*wfn.Attributes{
				{Part: "a", Vendor: "microsoft", Product: "ie", Version: "3\\.9"},
				{Part: "a", Vendor: "microsoft", Product: "ie", Version: "4\\.0"},
				{Part: "a", Vendor: "microsoft", Product: "ie", Version: "5\\.4"},
				{Part: "a", Vendor: "microsoft", Product: "ie", Version: "6\\.0"},
			},
			Matches: []*wfn.Attributes{
				{Part: "a", Vendor: "microsoft", Product: "ie", Version: "4\\.0"},
				{Part: "a", Vendor: "microsoft", Product: "ie", Version: "5\\.4"},
			},
			Expect: true,
		},
	}
	items, err := ParseJSON(bytes.NewBufferString(testJSONdict))
	if err != nil {
		t.Fatalf("failed to parse the dictionary: %v", err)
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			mm, ok := Match(c.Inventory, items[c.Rule].Config(), false)
			if ok != c.Expect {
				t.Fatalf("expected %t, got %t", c.Expect, ok)
			}
			if ok && !matchesAll(mm, c.Matches) {
				t.Fatalf("wrong match: expected %v, got %v", c.Matches, mm)
			}
		})
	}
}

func TestMatchJSONrequireVersion(t *testing.T) {
	inventory := []*wfn.Attributes{
		{Part: "a", Vendor: "microsoft", Product: "ie", Version: "6\\.0"},
	}
	items, err := ParseJSON(bytes.NewBufferString(testJSONdict))
	if err != nil {
		t.Fatalf("failed to parse the dictionary: %v", err)
	}
	if _, ok := Match(inventory, items[1].Config(), true); ok {
		t.Fatal("platform was expected to be ignored because of absence of version, but matched")
	}
}

func BenchmarkMatchJSON(b *testing.B) {
	inventory := []*wfn.Attributes{
		{Part: "o", Vendor: "microsoft", Product: "windows_xp", Update: "sp3"},
		{Part: "a", Vendor: "microsoft", Product: "ie", Version: "6\\.0"},
		{Part: "a", Vendor: "facebook", Product: "styx", Version: "0\\.1"},
	}
	items, err := ParseJSON(bytes.NewBufferString(testJSONdict))
	if err != nil {
		b.Fatalf("failed to parse the dictionary: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := Match(inventory, items[0].Config(), false); !ok {
			b.Fatal("expected Match to match, it did not")
		}
	}
}

var testJSONdict = `{
"CVE_data_type" : "CVE",
"CVE_data_format" : "MITRE",
"CVE_data_version" : "4.0",
"CVE_data_numberOfCVEs" : "7083",
"CVE_data_timestamp" : "2018-07-31T07:00Z",
"CVE_Items" : [
  {
    "cve" : {
      "data_type" : "CVE",
      "data_format" : "MITRE",
      "data_version" : "4.0",
      "CVE_data_meta" : {
        "ID" : "TESTVE-2018-0001",
        "ASSIGNER" : "cve@mitre.org"
      }
    },
    "configurations" : {
      "CVE_data_version" : "4.0",
      "nodes" : [
        {
          "operator" : "AND",
          "children" : [
            {
              "operator" : "OR",
              "cpe_match" : [ {
                "vulnerable" : true,
                  "cpe22Uri" : "cpe:/a:microsoft:ie:6.%01",
                  "cpe23Uri" : "cpe:2.3:a:microsoft:ie:6.*:*:*:*:*:*:*:*"
              } ]
            },
            {
              "operator" : "OR",
              "cpe_match" : [ {
                "vulnerable" : true,
                "cpe22Uri" : "cpe:/o:microsoft:windows_xp::sp%02",
                "cpe23Uri" : "cpe:2.3:o:microsoft:windows_xp:*:sp?:*:*:*:*:*:*"
              } ]
            }
          ]
        }
      ]
    }
  },
  {
    "cve" : {
      "data_type" : "CVE",
      "data_format" : "MITRE",
      "data_version" : "4.0",
      "CVE_data_meta" : {
        "ID" : "TESTVE-2018-0002",
        "ASSIGNER" : "cve@mitre.org"
      }
    },
    "configurations" : {
      "CVE_data_version" : "4.0",
      "nodes" : [
        {
          "operator" : "AND",
          "children" : [
            {
              "operator" : "OR",
              "cpe_match" : [ {
                "vulnerable" : true,
                  "cpe22Uri" : "cpe:/a:microsoft:ie",
                  "cpe23Uri" : "cpe:2.3:a:microsoft:ie:*:*:*:*:*:*:*:*",
                  "versionStartIncluding" : "4.0",
                  "versionEndExcluding" : "6.0"
              } ]
            }
          ]
        }
      ]
    }
  }
]
}`
