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
	"math"
)

func roundUp(x float64) float64 {
	// round up to one decimal
	return math.Ceil(x*10) / 10
}

// Score = combined score for the whole Vector
func (v Vector) Score() float64 {
	// combines all of them
	return v.EnvironmentalScore()
}

func (v Vector) BaseScore() float64 {
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

func (v Vector) impactScore() float64 {
	iscBase := 1 -
		(1-v.BaseMetrics.Confidentiality.weight())*
			(1-v.BaseMetrics.Integrity.weight())*
			(1-v.BaseMetrics.Availability.weight())
	if v.baseScopeChanged() {
		return 7.52*(iscBase-0.029) - 3.25*math.Pow((iscBase-0.02), 15)
	} else {
		return 6.42 * iscBase
	}
}

func (v Vector) exploitabilityScore() float64 {
	return 8.22 *
		v.BaseMetrics.AttackVector.weight() *
		v.BaseMetrics.AttackComplexity.weight() *
		v.BaseMetrics.PrivilegesRequired.weight(v.baseScopeChanged()) *
		v.BaseMetrics.UserInteraction.weight()
}

func (v Vector) TemporalScore() float64 {
	return roundUp(v.BaseScore() *
		v.TemporalMetrics.ExploitCodeMaturity.weight() *
		v.TemporalMetrics.RemediationLevel.weight() *
		v.TemporalMetrics.ReportConfidence.weight())
}

func (v Vector) EnvironmentalScore() float64 {
	i, e := v.modifiedImpactScore(), v.modifiedExploitabilityScore()
	if i < 0 {
		return 0
	}
	c := 1.0
	if v.modifiedScopeChanged() {
		c = 1.08
	}

	return roundUp(roundUp(math.Min(c*(e+i), 10.0)) *
		v.TemporalMetrics.ExploitCodeMaturity.weight() *
		v.TemporalMetrics.RemediationLevel.weight() *
		v.TemporalMetrics.ReportConfidence.weight())
}

func (v Vector) modifiedImpactScore() float64 {
	var mc, mi, ma float64

	if v.EnvironmentalMetrics.ModifiedConfidentiality.defined() {
		mc = v.EnvironmentalMetrics.ModifiedConfidentiality.weight()
	} else {
		mc = v.BaseMetrics.Confidentiality.weight()
	}

	if v.EnvironmentalMetrics.ModifiedIntegrity.defined() {
		mi = v.EnvironmentalMetrics.ModifiedIntegrity.weight()
	} else {
		mi = v.BaseMetrics.Integrity.weight()
	}

	if v.EnvironmentalMetrics.ModifiedAvailability.defined() {
		ma = v.EnvironmentalMetrics.ModifiedAvailability.weight()
	} else {
		ma = v.BaseMetrics.Availability.weight()
	}

	iscModified := math.Min(
		1-(1-mc*v.EnvironmentalMetrics.ConfidentialityRequirement.weight())*
			(1-mi*v.EnvironmentalMetrics.IntegrityRequirement.weight())*
			(1-ma*v.EnvironmentalMetrics.AvailabilityRequirement.weight()),
		0.915,
	)
	if v.modifiedScopeChanged() {
		return 7.52*(iscModified-0.029) - 3.25*math.Pow((iscModified-0.02), 15)
	} else {
		return 6.42 * iscModified
	}
}

func (v Vector) modifiedExploitabilityScore() float64 {
	var mav, mac, mpr, mui float64

	if v.EnvironmentalMetrics.ModifiedAttackVector.defined() {
		mav = v.EnvironmentalMetrics.ModifiedAttackVector.weight()
	} else {
		mav = v.BaseMetrics.AttackVector.weight()
	}

	if v.EnvironmentalMetrics.ModifiedAttackComplexity.defined() {
		mac = v.EnvironmentalMetrics.ModifiedAttackComplexity.weight()
	} else {
		mac = v.BaseMetrics.AttackComplexity.weight()
	}

	if v.EnvironmentalMetrics.ModifiedPrivilegesRequired.defined() {
		mpr = v.EnvironmentalMetrics.ModifiedPrivilegesRequired.weight(v.modifiedScopeChanged())
	} else {
		mpr = v.BaseMetrics.PrivilegesRequired.weight(v.modifiedScopeChanged())
	}

	if v.EnvironmentalMetrics.ModifiedUserInteraction.defined() {
		mui = v.EnvironmentalMetrics.ModifiedUserInteraction.weight()
	} else {
		mui = v.BaseMetrics.UserInteraction.weight()
	}

	return 8.22 * mav * mac * mpr * mui
}

// scope functions

func (v Vector) baseScopeChanged() bool {
	return v.BaseMetrics.Scope == ScopeChanged
}

func (v Vector) modifiedScopeChanged() bool {
	if v.EnvironmentalMetrics.ModifiedScope.defined() {
		return v.EnvironmentalMetrics.ModifiedScope == ModifiedScope(ScopeChanged)
	}
	return v.baseScopeChanged()
}
