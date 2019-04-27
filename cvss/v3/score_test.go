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

func TestRoundUp(t *testing.T) {
	tests := map[float64]float64{
		1.50:  1.5,
		1.51:  1.6,
		1.54:  1.6,
		1.55:  1.6,
		1.56:  1.6,
		1.59:  1.6,
		-1.50: -1.5,
		-1.51: -1.5,
		-1.54: -1.5,
		-1.55: -1.5,
		-1.56: -1.5,
		-1.59: -1.5,
	}

	for x, expected := range tests {
		t.Run(fmt.Sprintf("roundUp(%.2f)=%.1f", x, expected), func(t *testing.T) {
			if actual := roundUp(x); expected != actual {
				t.Errorf("expected %.1f, actual %.1f", expected, actual)
			}
		})
	}
}

func TestScores(t *testing.T) {
	// random vector chosen and validated at:
	// https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H/E:P/RL:T/RC:C/AR:L/MAV:P/MPR:H/MS:C/MC:H/MI:N/MA:H
	v := NewVector()
	v.Parse("CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H/E:P/RL:T/RC:C/AR:L/MAV:P/MPR:H/MS:C/MC:H/MI:N/MA:H")

	if s := v.baseScore(); s != 6.8 {
		t.Errorf("base score expected to be %.1f, got %.1f", 6.8, s)
	}

	if s := v.temporalScore(); s != 6.2 {
		t.Errorf("temporal score expected to be %.1f, got %.1f", 6.2, s)
	}

	if s := v.environmentalScore(); s != 5.1 {
		t.Errorf("environmental score expected to be %.1f, got %.1f", 5.1, s)
	}
}

func BenchmarkScore(b *testing.B) {
	v := NewVector()
	v.Parse("CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H/E:P/RL:T/RC:C/AR:L/MAV:P/MPR:H/MS:C/MC:H/MI:N/MA:H")

	for i := 0; i < b.N; i++ {
		v.Score()
	}
}
