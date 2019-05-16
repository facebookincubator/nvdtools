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
	"math"
)

func roundTo1Decimal(x float64) float64 {
	// round up to one decimal
	return math.Round(x*10) / 10
}

// Score = combined score for the whole Vector
func (v Vector) Score() float64 {
	// combines all of them
	return v.environmentalScore()
}

func (v Vector) baseScore() float64 {
	return v.baseScoreWith(v.impactScore())
}

func (v Vector) temporalScore() float64 {
	return v.temporalScoreWith(v.impactScore())
}

func (v Vector) environmentalScore() float64 {
	ai := v.adjustedImpactScore()
	at := v.temporalScoreWith(ai)

	return roundTo1Decimal((at + (10-at)*v.WeightMust("CDP")) * v.WeightMust("TD"))
}

// helpers

func (v Vector) impactScore() float64 {
	return 10.41 * (1 - (1-v.WeightMust("C"))*(1-v.WeightMust("I"))*(1-v.WeightMust("A")))
}

func (v Vector) exploitabilityScore() float64 {
	return 20 * v.WeightMust("AV") * v.WeightMust("AC") * v.WeightMust("Au")
}

func (v Vector) adjustedImpactScore() float64 {
	return math.Min(
		10.0,
		10.41*(1-
			(1-v.WeightMust("C")*v.WeightMust("CR"))*
				(1-v.WeightMust("I")*v.WeightMust("IR"))*
				(1-v.WeightMust("A")*v.WeightMust("AR"))),
	)
}

func (v Vector) temporalScoreWith(impact float64) float64 {
	base := v.baseScoreWith(impact)
	return roundTo1Decimal(base * v.WeightMust("E") * v.WeightMust("RL") * v.WeightMust("RC"))
}

func (v Vector) baseScoreWith(impact float64) float64 {
	i, e := impact, v.exploitabilityScore()
	fi := 1.176
	if i == 0.0 {
		fi = 0.0
	}
	return roundTo1Decimal((0.6*i + 0.4*e - 1.5) * fi)
}
