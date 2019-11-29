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

package cvss2

import (
	"fmt"
	"testing"
)

func TestFromString(t *testing.T) {
	cases := []string{
		"(AV:N/AC:M/Au:S/C:P/I:N/A:N/E:U/RL:OF/RC:C)",
		"(AV:A/AC:L/Au:S/C:P/I:N/A:P/E:U/RL:OF/RC:C)",
		"(AV:L/AC:L/Au:S/C:P/I:N/A:C/E:U/RL:OF/RC:C)",
		"(AV:A/AC:L/Au:S/C:N/I:P/A:P/E:U/RL:OF/RC:C)",
		"(AV:N/AC:L/Au:N/C:P/I:N/A:N/E:POC/RL:U/RC:C)",
		"(AV:A/AC:L/Au:N/C:C/I:C/A:C/E:U/RL:OF/RC:C)",
		"(AV:L/AC:L/Au:S/C:N/I:N/A:C/E:U/RL:OF/RC:C)",
		"(AV:A/AC:L/Au:N/C:N/I:N/A:C/E:U/RL:OF/RC:C)",
		"(AV:L/AC:L/Au:S/C:P/I:N/A:N/E:U/RL:OF/RC:C)",
		"(AV:L/AC:M/Au:S/C:P/I:N/A:N/E:U/RL:OF/RC:C)",
		"(AV:A/AC:L/Au:N/C:N/I:N/A:P/E:U/RL:TF/RC:C)",
		"(AV:L/AC:L/Au:S/C:N/I:P/A:N/E:U/RL:OF/RC:C)",
		"(AV:L/AC:H/Au:S/C:P/I:P/A:P/E:U/RL:OF/RC:C)",
		"(AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/RL:OF/RC:C)",
		"(AV:A/AC:L/Au:N/C:P/I:N/A:C/E:U/RL:TF/RC:C)",
		"(AV:N/AC:M/Au:N/C:P/I:P/A:P/E:U/RL:TF/RC:C)",
		"(AV:L/AC:M/Au:S/C:C/I:C/A:C/E:U/RL:OF/RC:C)",
		"(AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U/RC:C)",
		"(AV:A/AC:L/Au:N/C:N/I:P/A:N/E:U/RL:OF/RC:C)",
		"(AV:N/AC:H/Au:N/C:N/I:P/A:N/E:U/RL:OF/RC:C)",
		"(AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U/RL:TF/RC:C)",
		"(AV:A/AC:M/Au:N/C:P/I:P/A:N/E:U/RL:OF/RC:C)",
		"(AV:A/AC:L/Au:N/C:N/I:N/A:P/E:U/RL:U/RC:C)",
		"(AV:A/AC:L/Au:S/C:N/I:N/A:C/E:U/RL:OF/RC:C)",
		"(AV:L/AC:L/Au:S/C:N/I:N/A:P/E:U/RL:OF/RC:C)",
		"(AV:L/AC:L/Au:S/C:N/I:N/A:P/E:U/RL:OF/RC:C/ME:U/MRL:OF/MRC:C)",
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

func BenchmarkParse(b *testing.B) {
	for i := 0; i < b.N; i++ {
		// all possible metrics are defined in this string
		VectorFromString("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R/CR:H/IR:M/AR:L/MAV:P/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:L/MA:H/ME:U/MRL:OF/MRC:C")
	}
}

func TestAbsorb(t *testing.T) {
	v1, _ := VectorFromString("(E:U/RL:OF/RC:UR)")
	v2, _ := VectorFromString("(E:H/RL:TF)")

	v1.Absorb(v2)
	// should take values from v2, but only those which are defined. So RC should stay R
	if v1.String() != "(E:H/RL:TF/RC:UR)" {
		t.Errorf("when absorbing only defined values from another vector, it shouldn't override undefined ones")
	}
}
