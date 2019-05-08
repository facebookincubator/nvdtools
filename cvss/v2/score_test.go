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

package v2

import (
	"fmt"
	"testing"
)

func TestRoundTo1Decimal(t *testing.T) {
	tests := map[float64]float64{
		1.50:  1.5,
		1.51:  1.5,
		1.54:  1.5,
		1.55:  1.6,
		1.56:  1.6,
		1.59:  1.6,
		-1.50: -1.5,
		-1.51: -1.5,
		-1.54: -1.5,
		-1.55: -1.6,
		-1.56: -1.6,
		-1.59: -1.6,
	}

	for x, expected := range tests {
		t.Run(fmt.Sprintf("roundTo1Decimal(%.2f)=%.1f", x, expected), func(t *testing.T) {
			if actual := roundTo1Decimal(x); expected != actual {
				t.Errorf("expected %.1f, actual %.1f", expected, actual)
			}
		})
	}
}

func TestScores(t *testing.T) {
	// random vector chosen and validated at:
	// https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?calculator&adv&version=2
	v := NewVector()
	v.Parse("(AV:A/AC:L/Au:S/C:C/I:P/A:C/E:F/RL:W/RC:UR/CDP:MH/TD:M/CR:M/IR:L/AR:H)")

	if s := v.baseScore(); s != 7.4 {
		t.Errorf("base score expected to be %.1f, got %.1f", 7.4, s)
	}

	if s := v.temporalScore(); s != 6.3 {
		t.Errorf("temporal score expected to be %.1f, got %.1f", 6.3, s)
	}

	if s := v.environmentalScore(); s != 6.0 {
		t.Errorf("environmental score expected to be %.1f, got %.1f", 6.0, s)
	}
}

func BenchmarkScore(b *testing.B) {
	v := NewVector()
	v.Parse("(AV:A/AC:L/Au:S/C:C/I:P/A:C/E:F/RL:W/RC:UR/CDP:MH/TD:M/CR:M/IR:L/AR:H)")

	for i := 0; i < b.N; i++ {
		v.Score()
	}
}
