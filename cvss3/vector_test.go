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

package cvss3

import (
	"fmt"
	"testing"
)

func TestVersionFromString(t *testing.T) {
	for i, c := range []struct {
		s    string
		v    version
		fail bool
	}{
		{"3.0", version(0), false},
		{"3.1", version(1), false},
		{"3.2", version(0), true},
	} {
		t.Run(fmt.Sprintf("case %2d", i+1), func(t *testing.T) {
			if v, err := versionFromString(c.s); err != nil {
				if !c.fail {
					t.Fatal(err)
				}
			} else if c.fail {
				t.Fatalf("versionFromString(%q) should've failed, but didn't", c.s)
			} else if v != c.v {
				t.Fatalf("versionFromString(%q) = %v, but got %v", c.s, c.v, v)
			}
		})
	}
}

func TestVersionInVector(t *testing.T) {
	for i, c := range []struct {
		vec string
		ver version
	}{
		{"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C", version(0)},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C", version(1)},
	} {
		t.Run(fmt.Sprintf("case %2d", i+1), func(t *testing.T) {
			if v, err := VectorFromString(c.vec); err != nil {
				t.Fatal(err)
			} else if v.version != c.ver {
				t.Fatalf("version(%q) = %v, but got %v", c.vec, c.ver, v.version)
			}
		})
	}
}

func TestFromString(t *testing.T) {
	cases := []string{
		"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/E:U/RL:O/RC:C",
		"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C",
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N/E:U/RL:O/RC:C",
		"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H/E:U/RL:T/RC:C",
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C",
		"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H/E:U/RL:T/RC:C",
		"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N/E:U/RL:T/RC:C",
		"CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N/E:U/RL:U/RC:C",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N/E:U/RL:U/RC:C",
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:P/RL:T/RC:C",
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N/E:F/RL:O/RC:C",
		"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N/E:U/RL:U/RC:C",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:T/RC:C",
		"CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N/E:U/RL:O/RC:C",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N/E:U/RL:T/RC:C",
		"CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:U/RC:C",
		"CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C",
		"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:O/RC:C",
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N/E:U/RL:U/RC:C",
		"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N/E:U/RL:T/RC:C",
		"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N/E:P/RL:U/RC:C",
		"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N/E:U/RL:T/RC:C",
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N/E:U/RL:O/RC:C",
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/RL:T/RC:C",
		"CVSS:3.1/AV:N/AC:L/PR:N/ME:U/MRL:T/MRC:R",
	}

	for i, str := range cases {
		str := str
		t.Run(fmt.Sprintf("case %2d", i+1), func(t *testing.T) {
			if v, err := VectorFromString(str); err != nil {
				t.Errorf("unable to parse vector: %v", err)
			} else if v.String() != str {
				t.Errorf("vector.String() should be the same thing it was parsed from.\nGot:\t%s\nExpect:\t%s", v, str)
			}
		})
	}
}

//Not defined environmental metrics should not be serialized into the vector string
func TestToString(t *testing.T) {
	for i, c := range []struct {
		vecWithNotDefined    string
		vecWithoutNotDefined string
	}{
		{"CVSS:3.0/AC:L/UI:N/S:U/I:H/A:H/E:H/RL:O/RC:C/CR:X/MAC:X/MC:X", "CVSS:3.0/AC:L/UI:N/S:U/I:H/A:H/E:H/RL:O/RC:C"},
		{"CVSS:3.1/AC:L/UI:N/S:U/I:H/A:H/E:H/RL:O/RC:C/CR:X/MAC:X/MC:X", "CVSS:3.1/AC:L/UI:N/S:U/I:H/A:H/E:H/RL:O/RC:C"},
		{"CVSS:3.0/AV:N/AC:L/PR:N/ME:X/MRL:X/MRC:X", "CVSS:3.0/AV:N/AC:L/PR:N"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/ME:X/MRL:X/MRC:X", "CVSS:3.1/AV:N/AC:L/PR:N"},
	} {
		t.Run(fmt.Sprintf("case %2d", i+1), func(t *testing.T) {
			if v, err := VectorFromString(c.vecWithNotDefined); err != nil {
				t.Errorf("unable to parse vector: %v", err)
			} else if v.String() != c.vecWithoutNotDefined {
				t.Errorf("vector.String() should be the same thing it was parsed from but withoud Not Defined metrics.\nGot:\t%s\nExpect:\t%s", v, c.vecWithoutNotDefined)
			}
		})
	}
}

func BenchmarkParse(b *testing.B) {
	for i := 0; i < b.N; i++ {
		// all possible metrics are defined in this string
		VectorFromString("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R/CR:H/IR:M/AR:L/MAV:P/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:L/MA:H/ME:U/MRL:T/MRC:R")
	}
}

func TestAbsorb(t *testing.T) {
	v1, _ := VectorFromString("CVSS:3.0/E:U/RL:W/RC:R")
	v2, _ := VectorFromString("CVSS:3.0/E:H/RL:T")

	v1.Absorb(v2)
	// should take values from v2, but only those which are defined. So RC should stay R
	if v1.String() != "CVSS:3.0/E:H/RL:T/RC:R" {
		t.Errorf("when absorbing only defined values from another vector, it shouldn't override undefined ones")
	}
}
