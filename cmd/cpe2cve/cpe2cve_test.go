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

package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/jokLiu/nvdtools/cvefeed"
)

func TestAppendAt(t *testing.T) {
	skip := getSkip([]int{1, 3})
	cases := []struct {
		tgt          []string
		pos          []int
		replacements []string
		out          []string
	}{
		{
			tgt:          []string{"skip", "hello", "replace"},
			pos:          []int{2, 1},
			replacements: []string{"world", "beautiful"},
			out:          []string{"hello", "beautiful", "world"},
		},
	}
	for _, c := range cases {
		var args []interface{}
		for i, v := range c.pos {
			args = append(args, v, c.replacements[i])
		}
		out := skip.appendAt(c.tgt, args...)
		if strings.Join(out, " ") != strings.Join(c.out, " ") {
			t.Errorf("got %v, expected %v", out, c.out)
		}
	}
}

func TestProcessInput(t *testing.T) {
	cases := []struct {
		in  string
		out [][]string
	}{
		{"", [][]string{{""}}},
		{
			in: "1,2,3,cpe:/o:microsoft:windows_10:-::~~~~x64~+cpe:/a:adobe:flash_player:24.0.0.194,5,6,7,8,9,10",
			out: [][]string{
				{
					"2|cpe:/o:microsoft:windows_10:-::~~~~x64~&cpe:/a:adobe:flash_player:24.0.0.194|5|6|7|CVE-2016-0165|cpe:/o:microsoft:windows_10:::~~~~x64~|8|9|10",
				},
				{
					"2|cpe:/o:microsoft:windows_10:-::~~~~x64~&cpe:/a:adobe:flash_player:24.0.0.194|5|6|7|CVE-2666-1337|cpe:/o:microsoft:windows_10:::~~~~x64~&cpe:/a:adobe:flash_player:24.0.0.194|8|9|10",
					"2|cpe:/o:microsoft:windows_10:-::~~~~x64~&cpe:/a:adobe:flash_player:24.0.0.194|5|6|7|CVE-2666-1337|cpe:/a:adobe:flash_player:24.0.0.194&cpe:/o:microsoft:windows_10:::~~~~x64~|8|9|10",
				},
			},
		},
		// TODO: add more test cases
	}
	testDictXML, err := cvefeed.ParseXML(strings.NewReader(testDictXMLStr))
	if err != nil {
		t.Fatalf("couldn't parse XML dictionary: %v", err)
	}
	cacheXML := cvefeed.NewCache(testDictXML)
	testDictJSON, err := cvefeed.ParseJSON(strings.NewReader(testDictJSONStr))
	if err != nil {
		t.Fatalf("couldn't parse JSON dictionary: %v", err)
	}
	cacheJSON := cvefeed.NewCache(testDictJSON)
	cfg := config{
		nProcessors: 2,
		cpesAt:      4,
		cvesAt:      6,
		matchesAt:   7,
		inFieldSep:  ",",
		outFieldSep: "|",
		inRecSep:    "+",
		outRecSep:   "&",
		cpuProfile:  "",
		memProfile:  "",
		skip:        getSkip([]int{1, 3}),
	}
	for cacheID, cache := range []*cvefeed.Cache{cacheXML, cacheJSON} {
		for i, c := range cases {
			c := c
			t.Run(fmt.Sprintf("cache#%d case #%d", cacheID+1, i+1), func(t *testing.T) {
				var w bytes.Buffer
				r := strings.NewReader(c.in)
				done := processInput(r, &w, cache, cfg)
				<-done
				got := strings.Split(strings.TrimSpace(w.String()), "\n")
				if len(got) != len(c.out) {
					t.Fatalf("got %d lines but %d were expected:\ngot:\n%q\n", len(got), len(c.out), strings.Join(got, "\n"))
				}
				for _, s := range got {
					found := false
					for _, oneOf := range c.out {
						if contains(oneOf, s) {
							found = true
						}
					}
					if !found {
						t.Fatalf("got:\n%q\nexpected one of:%v", s, c.out)
					}
				}
			})
		}
	}
}

// This used to cause false postives, added this test during the debug session
func TestProcessInputFalsePositives(t *testing.T) {
	in := "cpe:/a::glibc:2.27-1"
	dict, err := cvefeed.ParseJSON(strings.NewReader(testDictJSONStr2))
	if err != nil {
		t.Fatalf("couldn't parse JSON dictionary: %v", err)
	}
	cache := cvefeed.NewCache(dict)
	cfg := config{
		nProcessors: 2,
		cpesAt:      1,
		cvesAt:      3,
		matchesAt:   2,
		inFieldSep:  ",",
		inRecSep:    ";",
		outFieldSep: ",",
		outRecSep:   ";",
	}
	var w bytes.Buffer
	r := strings.NewReader(in)
	done := processInput(r, &w, cache, cfg)
	<-done
	out := strings.TrimSpace(w.String())
	if out != "" {
		t.Fatalf("got a false positive match:\n%s\nyielded\n%s", in, out)
	}
}

func TestProcessInputRequireVersion(t *testing.T) {
	in := "cpe:/h:huaweidevice:d100:1.33.7"
	dict, err := cvefeed.ParseJSON(strings.NewReader(testDictJSONStr2))
	if err != nil {
		t.Fatalf("couldn't parse JSON dictionary: %v", err)
	}
	cache := cvefeed.NewCache(dict).SetRequireVersion(true)
	cfg := config{
		nProcessors:    2,
		cpesAt:         1,
		cvesAt:         3,
		matchesAt:      2,
		inFieldSep:     ",",
		inRecSep:       ";",
		outFieldSep:    ",",
		outRecSep:      ";",
		requireVersion: true,
	}
	var w bytes.Buffer
	r := strings.NewReader(in)
	done := processInput(r, &w, cache, cfg)
	<-done
	out := strings.TrimSpace(w.String())
	if out != "" {
		t.Fatalf("got a match that should've been ignored due to an absence of version:\n%s\nyielded\n%s", in, out)
	}
}

func BenchmarkProcessInputXML(t *testing.B) {
	in := `1;2;3;cpe:/o:microsoft:windows_10:-::~~~~x64~,cpe:/a:adobe:flash_player:24.0.0.194
1;2;3;cpe:/o::centos_linux:7.5.1804,cpe:/a::chardet:2.2.1,cpe:/a::javapackages:1.0.0,cpe:/a::kitchen:1.1.1,cpe:/a::nose:1.3.7,cpe:/a::python-dateutil:1.5,cpe:/a::pytz:2016.10,cpe:/a::setuptools:0.9.8,cpe:/a::chardet:2.2.1,cpe:/a::javapackages:1.0.0,cpe:/a::kitchen:1.1.1,cpe:/a::nose:1.3.7,cpe:/a::python-dateutil:1.5,cpe:/a::pytz:2016.10,cpe:/a::setuptools:0.9.8
1;2;3;cpe:/o::centos_linux:7.5.1804,cpe:/a::chardet:2.2.1,cpe:/a::kitchen:1.1.1,cpe:/a::chardet:2.2.1,cpe:/a::kitchen:1.1.1,cpe:/a::chardet:2.2.1,cpe:/a::kitchen:1.1.1
`
	testDict, err := cvefeed.ParseXML(strings.NewReader(testDictXMLStr))
	if err != nil {
		t.Fatalf("couldn't parse dictionary: %v", err)
	}
	cache := cvefeed.NewCache(testDict)
	cfg := config{
		nProcessors: 1,
		cpesAt:      4,
		cvesAt:      5,
		matchesAt:   6,
		inFieldSep:  ";",
		outFieldSep: "|",
		inRecSep:    ",",
		outRecSep:   "&",
		cpuProfile:  "",
		memProfile:  "",
	}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		var w bytes.Buffer
		r := strings.NewReader(in)
		done := processInput(r, &w, cache, cfg)
		<-done
	}
}

func BenchmarkProcessInputJSON(t *testing.B) {
	in := `1;2;3;cpe:/o:microsoft:windows_10:-::~~~~x64~,cpe:/a:adobe:flash_player:24.0.0.194
1;2;3;cpe:/o::centos_linux:7.5.1804,cpe:/a::chardet:2.2.1,cpe:/a::javapackages:1.0.0,cpe:/a::kitchen:1.1.1,cpe:/a::nose:1.3.7,cpe:/a::python-dateutil:1.5,cpe:/a::pytz:2016.10,cpe:/a::setuptools:0.9.8,cpe:/a::chardet:2.2.1,cpe:/a::javapackages:1.0.0,cpe:/a::kitchen:1.1.1,cpe:/a::nose:1.3.7,cpe:/a::python-dateutil:1.5,cpe:/a::pytz:2016.10,cpe:/a::setuptools:0.9.8
1;2;3;cpe:/o::centos_linux:7.5.1804,cpe:/a::chardet:2.2.1,cpe:/a::kitchen:1.1.1,cpe:/a::chardet:2.2.1,cpe:/a::kitchen:1.1.1,cpe:/a::chardet:2.2.1,cpe:/a::kitchen:1.1.1
`
	testDict, err := cvefeed.ParseJSON(strings.NewReader(testDictJSONStr))
	if err != nil {
		t.Fatalf("couldn't parse dictionary: %v", err)
	}
	cache := cvefeed.NewCache(testDict)
	cfg := config{
		nProcessors: 1,
		cpesAt:      4,
		cvesAt:      5,
		matchesAt:   6,
		inFieldSep:  ";",
		outFieldSep: "|",
		inRecSep:    ",",
		outRecSep:   "&",
		cpuProfile:  "",
		memProfile:  "",
	}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		var w bytes.Buffer
		r := strings.NewReader(in)
		done := processInput(r, &w, cache, cfg)
		<-done
	}
}

func getSkip(ff []int) fieldsToSkip {
	set := make(map[int]struct{})
	for _, f := range ff {
		set[f-1] = struct{}{}
	}
	return fieldsToSkip(set)
}

func contains(in []string, s string) bool {
	for _, t := range in {
		if t == s {
			return true
		}
	}
	return false
}

var testDictXMLStr = `
<?xml version='1.0' encoding='UTF-8'?>
<nvd>
  <entry id="CVE-2016-0165">
    <vuln:vulnerable-configuration id="http://nvd.nist.gov/">
      <cpe-lang:logical-test operator="OR" negate="false">
        <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_10:-"/>
        <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_10:1511"/>
        <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_7::sp1"/>
        <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_8.1"/>
        <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_rt_8.1:-"/>
        <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_server_2008::sp2"/>
        <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_server_2008:r2:sp1"/>
        <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_server_2012:-"/>
        <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_server_2012:r2"/>
        <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_vista::sp2"/>
      </cpe-lang:logical-test>
    </vuln:vulnerable-configuration>
  </entry>
  <entry id="CVE-2666-1337">
    <vuln:vulnerable-configuration id="http://nvd.nist.gov/">
      <cpe-lang:logical-test operator="AND" negate="false">
        <cpe-lang:logical-test operator="OR" negate="false">
          <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_10"/>
        </cpe-lang:logical-test>
        <cpe-lang:logical-test operator="OR" negate="false">
          <cpe-lang:fact-ref name="cpe:/a:adobe:flash_player:24.0.0.194"/>
        </cpe-lang:logical-test>
      </cpe-lang:logical-test>
    </vuln:vulnerable-configuration>
  </entry>
  <entry id="CVE-2666-6969">
    <vuln:vulnerable-configuration id="http://nvd.nist.gov/">
      <cpe-lang:logical-test operator="AND" negate="false">
        <cpe-lang:logical-test operator="OR" negate="false">
          <cpe-lang:fact-ref name="cpe:/o:microsoft:windows_10"/>
        </cpe-lang:logical-test>
        <cpe-lang:logical-test operator="OR" negate="false">
          <cpe-lang:fact-ref name="cpe:/a:adobe:flash_player:24.0.1"/>
        </cpe-lang:logical-test>
      </cpe-lang:logical-test>
    </vuln:vulnerable-configuration>
  </entry>
</nvd>
`

var testDictJSONStr = `{
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
        "ID" : "CVE-2016-0165",
        "ASSIGNER" : "cve@mitre.org"
      }
    },
    "configurations" : {
      "CVE_data_version" : "4.0",
      "nodes" : [
        {
          "operator" : "OR",
          "cpe_match" : [
            {
              "vulnerable" : true,
              "cpe22Uri" : "cpe:/o:microsoft:windows_10:-"
            },
            {
              "vulnerable" : true,
              "cpe22Uri" : "cpe:/o:microsoft:windows_10:1511"
            },
            {
              "vulnerable" : true,
              "cpe22Uri" : "cpe:/o:microsoft:windows_7::sp1"
            },
            {
              "vulnerable" : true,
              "cpe22Uri" : "cpe:/o:microsoft:windows_8.1"
            },
            {
              "vulnerable" : true,
              "cpe22Uri" : "cpe:/o:microsoft:windows_rt_8.1:-"
            },
            {
              "vulnerable" : true,
              "cpe22Uri" : "cpe:/o:microsoft:windows_server_2008::sp2"
            },
            {
              "vulnerable" : true,
              "cpe22Uri" : "cpe:/o:microsoft:windows_server_2008:r2:sp1"
            },
            {
              "vulnerable" : true,
              "cpe22Uri" : "cpe:/o:microsoft:windows_server_2012:-"
            },
            {
              "vulnerable" : true,
              "cpe22Uri" : "cpe:/o:microsoft:windows_server_2012:r2"
            },
            {
              "vulnerable" : true,
              "cpe22Uri" : "cpe:/o:microsoft:windows_vista::sp2"
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
        "ID" : "CVE-2666-1337",
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
              "cpe_match" : [
                {
                  "vulnerable" : true,
                  "cpe22Uri" : "cpe:/o:microsoft:windows_10"
                }
              ]
            },
            {
              "operator" : "OR",
              "cpe_match" : [
                {
                  "vulnerable" : true,
                  "cpe22Uri" : "cpe:/a:adobe:flash_player:24.0.0.194"
                }
              ]
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
        "ID" : "CVE-2666-6969",
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
              "cpe_match" : [
                {
                  "vulnerable" : true,
                  "cpe22Uri" : "cpe:/o:microsoft:windows_10"
                }
              ]
            },
            {
              "operator" : "OR",
              "cpe_match" : [
                {
                  "vulnerable" : true,
                  "cpe22Uri" : "cpe:/a:adobe:flash_player:24.0.1"
                }
              ]
            }
          ]
        }
      ]
    }
  }
]
}`

var testDictJSONStr2 = `{"CVE_data_format":"","CVE_data_type":"","CVE_data_version":"","CVE_Items":[{"cve":{"affects":{"vendor":{"vendor_data":[{"product":{"product_data":[{"product_name":"d100","version":{"version_data":[{"version_value":"*"}]}}]},"vendor_name":"huaweidevice"}]}},"CVE_data_meta":{"ASSIGNER":"cve@mitre.org","ID":"CVE-2009-2273"},"data_format":"MITRE","data_type":"CVE","data_version":"4.0","description":{"description_data":[{"lang":"en","value":"The default configuration of the Wi-Fi component on the Huawei D100 does not use encryption, which makes it easier for remote attackers to obtain sensitive information by sniffing the network."}]},"problemtype":{"problemtype_data":[{"description":[{"lang":"en","value":"CWE-310"}]}]},"references":{"reference_data":[{"name":"20090630 Multiple Flaws in Huawei D100","refsource":"BUGTRAQ","url":"http://www.securityfocus.com/archive/1/archive/1/504645/100/0/threaded"}]}},"configurations":{"CVE_data_version":"4.0","nodes":[{"cpe":[{"cpe22Uri":"cpe:/h:huaweidevice:d100","cpe23Uri":"cpe:2.3:h:huaweidevice:d100:*:*:*:*:*:*:*:*","vulnerable":true}],"operator":"AND"}]},"impact":{"baseMetricV2":{"cvssV2":{"accessComplexity":"LOW","accessVector":"NETWORK","authentication":"NONE","availabilityImpact":"NONE","baseScore":5,"confidentialityImpact":"PARTIAL","integrityImpact":"NONE","vectorString":"(AV:N/AC:L/Au:N/C:P/I:N/A:N)","version":"2.0"},"exploitabilityScore":10,"impactScore":2.9,"severity":"MEDIUM"}},"lastModifiedDate":"2009-07-01T04:00Z","publishedDate":"2009-07-01T13:00Z"}]}`
