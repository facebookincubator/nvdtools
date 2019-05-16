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
	"strings"

	"github.com/facebookincubator/nvdtools/cvss/common"
)

const (
	prefix     = "CVSS:3.0/"
	notDefined = "X"
)

var (
	weights map[string]map[string]float64 // main weights, filled with the ones below

	baseMetricsWeights = map[string]map[string]float64{
		"AV": { // Attack Vector
			"N": 0.85, // Network
			"A": 0.62, // Adjecent
			"L": 0.55, // Local
			"P": 0.20, // Physical
		},
		"AC": { // Attack Complexity
			"L": 0.77, // Low
			"H": 0.44, // High
		},
		"PR": { // Privileges Required
			"N": 0.85, // None
			"L": 0.62, // Low; 0.68 if Scope changed
			"H": 0.27, // High; 0.50 if Scope changed
		},
		"UI": { // User Interaction
			"N": 0.85, // None
			"R": 0.62, // Required
		},
		"S": { // Scope; no values, but need the keys
			"U": 0.0, // Unchanged
			"C": 0.0, // Changed
		},
		"C": { // Confidentiality
			"H": 0.56, // High
			"L": 0.22, // Low
			"N": 0.00, // None
		},
		"I": {
			"H": 0.56, // High
			"L": 0.22, // Low
			"N": 0.00, // None
		},
		"A": {
			"H": 0.56, // High
			"L": 0.22, // Low
			"N": 0.00, // None
		},
	}

	temporalMetricsWeights = map[string]map[string]float64{
		"E": { // Exploit Code Maturity
			notDefined: 1.00, // Not defined
			"H":        1.00, // High
			"F":        0.97, // Functional
			"P":        0.94, // Proof-Of-Concept
			"U":        0.91, // Unproven
		},
		"RL": { // Remediation Level
			notDefined: 1.00, // Not defined
			"U":        1.00, // Unavailable
			"W":        0.97, // Workaround
			"T":        0.96, // Temporary Fix
			"O":        0.95, // Official Fix
		},
		"RC": { // Report Confidence
			notDefined: 1.00, // Not defined
			"C":        1.00, // Confirmed
			"R":        0.96, // Reasonable
			"U":        0.92, // Unknown
		},
	}
	environmentalMetricsWeights = map[string]map[string]float64{
		"CR": { // Confidentiality Requirement
			notDefined: 1.00, // Not defined
			"H":        1.50, // High
			"M":        1.00, // Medium
			"L":        0.50, // Low
		},
		"IR": { // Integrity Requirement
			notDefined: 1.00, // Not defined
			"H":        1.50, // High
			"M":        1.00, // Medium
			"L":        0.50, // Low
		},
		"AR": { // Availability Requirement
			notDefined: 1.00, // Not defined
			"H":        1.50, // High
			"M":        1.00, // Medium
			"L":        0.50, // Low
		},
		// + the ones from base vector, see init function below
	}
)

func init() {
	// create weights
	weights = make(map[string]map[string]float64)
	for metric, values := range baseMetricsWeights {
		weights[metric] = values
		weights["M"+metric] = values // environmental
	}
	for metric, values := range temporalMetricsWeights {
		weights[metric] = values
	}
	for metric, values := range environmentalMetricsWeights {
		weights[metric] = values
	}
}

type Vector struct {
	common.Metrics
}

func NewVector() Vector {
	return Vector{common.NewMetrics(weights, notDefined)}
}

func (v Vector) Validate() error {
	for metric := range baseMetricsWeights {
		if _, err := v.Get(metric); err != nil {
			return fmt.Errorf("base vector: metric %q not defined", metric)
		}
	}
	return nil
}

// Override Parse and String to remove/add prefix

func (v Vector) Parse(str string) error {
	// remove prefix if exists
	if strings.HasPrefix(strings.ToUpper(str), prefix) {
		str = str[len(prefix):]
	}
	return v.Metrics.Parse(str)
}

func (v Vector) String() string {
	return prefix + v.Metrics.String()
}

// weight functions

func (v Vector) modifiedWeight(metric string) float64 {
	// get M${metric} from environmental vector
	// if it's not defined, then get the same for $metric from the base vector
	if w, err := v.Weight("M" + metric); err == nil {
		return w
	}
	return v.WeightMust(metric)
}

func (v Vector) prWeight() float64 {
	return v.prWeightWith(v.baseScopeChanged())
}

func (v Vector) modifiedPRWeight() float64 {
	msc := v.modifiedScopeChanged()
	if msc {
		if mpr, err := v.Get("MPR"); err == nil {
			if mpr == "L" {
				return 0.68
			} else if mpr == "H" {
				return 0.50
			}
		}
	}
	return v.prWeightWith(msc)
}

func (v Vector) prWeightWith(scopeChanged bool) float64 {
	if scopeChanged {
		pr, err := v.Get("PR")
		if err != nil {
			panic(err) // must be present because of Validate
		}

		if pr == "L" {
			return 0.68
		} else if pr == "H" {
			return 0.50
		}
	}
	return v.WeightMust("PR")
}

// scope functions

func (v Vector) baseScopeChanged() bool {
	// base scope must be defined
	if scope, err := v.Get("S"); err == nil {
		return scope == "C"
	}
	panic("scope not defined in base vector") // won't happen because of validate
}

func (v Vector) modifiedScopeChanged() bool {
	// try to get modified scope first
	// if it's not defined then get the base scope
	if scope, err := v.Get("MS"); err == nil {
		return scope == "C"
	}
	return v.baseScopeChanged()
}
