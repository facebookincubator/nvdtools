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

package v3

import (
	"fmt"
	"testing"
)

func TestParse(t *testing.T) {
	// all possible metrics are defined in these 3 strings
	base := "AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L"
	temporal := "E:U/RL:T/RC:R"
	environmental := "CR:H/IR:M/AR:L/MAV:P/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:L/MA:H"

	v := NewVector()
	if err := v.Parse(base); err != nil {
		t.Fatal(err)
	}
	if err := v.Parse(temporal); err != nil {
		t.Fatal(err)
	}
	if err := v.Parse(environmental); err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		// base vector
		"AV": "P",
		"AC": "H",
		"PR": "L",
		"UI": "R",
		"S":  "C",
		"C":  "L",
		"I":  "L",
		"A":  "L",
		// temporal vector
		"E":  "U",
		"RL": "T",
		"RC": "R",
		// environmental vector
		"CR":  "H",
		"IR":  "M",
		"AR":  "L",
		"MAV": "P",
		"MAC": "H",
		"MPR": "L",
		"MUI": "R",
		"MS":  "U",
		"MC":  "L",
		"MI":  "L",
		"MA":  "H",
	}

	for metric, value := range tests {
		t.Run(fmt.Sprintf("v[%s]=%s", metric, value), func(t *testing.T) {
			if val, err := v.Get(metric); err != nil {
				t.Fatal(err)
			} else if val != value {
				t.Errorf("expecting %s, got %s", value, val)
			}
		})
	}
}

func BenchmarkParse(b *testing.B) {
	// all possible metrics are defined in these 3 strings
	base := "AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L"
	temporal := "E:U/RL:T/RC:R"
	environmental := "CR:H/IR:M/AR:L/MAV:P/MAC:H/MPR:L/MUI:R/MS:U/MC:L/MI:L/MA:H"

	v := NewVector()
	for i := 0; i < b.N; i++ {
		v.Parse(base)
		v.Parse(temporal)
		v.Parse(environmental)
	}
}
