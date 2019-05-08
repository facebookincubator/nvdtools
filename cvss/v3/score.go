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
	"math"
)

func roundUp(x float64) float64 {
	// round up to one decimal
	return math.Ceil(x*10) / 10
}

// Score = combined score for the whole Vector
func (v Vector) Score() float64 {
	// combines all of them
	return v.environmentalScore()
}

func (v Vector) baseScore() float64 {
	i, e := v.impactScore(), v.exploitabilityScore()
	if i < 0 {
		return 0
	}
	c := 1.0
	if v.baseScopeChanged() {
		c = 1.08
	}

	return roundUp(math.Min(c*(e+i), 10.0))
}

func (v Vector) temporalScore() float64 {
	return roundUp(v.baseScore() * v.WeightDefault("E", 1.0) * v.WeightDefault("RL", 1.0) * v.WeightDefault("RC", 1.0))
}

func (v Vector) environmentalScore() float64 {
	i, e := v.modifiedImpactScore(), v.modifiedExploitabilityScore()
	if i < 0 {
		return 0
	}
	c := 1.0
	if v.modifiedScopeChanged() {
		c = 1.08
	}

	return roundUp(roundUp(math.Min(c*(e+i), 10.0)) * v.WeightDefault("E", 1.0) * v.WeightDefault("RL", 1.0) * v.WeightDefault("RC", 1.0))
}

// helpers

func (v Vector) impactScore() float64 {
	iscBase := 1 - (1-v.WeightMust("C"))*(1-v.WeightMust("I"))*(1-v.WeightMust("A"))
	if v.baseScopeChanged() {
		return 7.52*(iscBase-0.029) - 3.25*math.Pow((iscBase-0.02), 15)
	} else {
		return 6.42 * iscBase
	}
}

func (v Vector) exploitabilityScore() float64 {
	return 8.22 * v.WeightMust("AV") * v.WeightMust("AC") * v.prWeight() * v.WeightMust("UI")
}

func (v Vector) modifiedImpactScore() float64 {
	iscModified := math.Min(
		1-(1-v.modifiedWeight("C")*v.WeightDefault("CR", 1.0))*
			(1-v.modifiedWeight("I")*v.WeightDefault("IR", 1.0))*
			(1-v.modifiedWeight("A")*v.WeightDefault("AR", 1.0)),
		0.915,
	)
	if v.modifiedScopeChanged() {
		return 7.52*(iscModified-0.029) - 3.25*math.Pow((iscModified-0.02), 15)
	} else {
		return 6.42 * iscModified
	}
}

func (v Vector) modifiedExploitabilityScore() float64 {
	return 8.22 * v.modifiedWeight("AV") * v.modifiedWeight("AC") * v.modifiedPRWeight() * v.modifiedWeight("UI")
}
