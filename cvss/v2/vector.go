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
	"strings"

	"github.com/facebookincubator/nvdtools/cvss/common"
)

const (
	notDefined = "ND"
)

var (
	weights = map[string]map[string]float64{

		// base metrics
		"AV": { // Access Vector
			"L": 0.395, // Local
			"A": 0.646, // Adjecent Network
			"N": 1.000, // Network
		},
		"AC": { // Access Complexity
			"H": 0.35, // High
			"M": 0.61, // Medium
			"L": 0.71, // Low
		},
		"Au": { // Authentication
			"M": 0.45,  // Multiple
			"S": 0.56,  // Single
			"N": 0.704, // None
		},
		"C": { // Confidentiality Impact
			"N": 0.0,   // None
			"P": 0.275, // Partial
			"C": 0.660, // Complete
		},
		"I": { // Integrity Impact
			"N": 0.0,   // None
			"P": 0.275, // Partial
			"C": 0.660, // Complete
		},
		"A": { // Availability Impact
			"N": 0.0,   // None
			"P": 0.275, // Partial
			"C": 0.660, // Complete
		},

		// temporal metrics
		"E": { // Exploitability
			"U":        0.85, // Unproven
			"POC":      0.90, // Proof-Of-Concept
			"F":        0.95, // Functional
			"H":        1.00, // High
			notDefined: 1.00, // Not Defined
		},
		"RL": { // Remediation Level
			"OF":       0.87, // Official Fix
			"TF":       0.90, // Temporary Fix
			"W":        0.95, // Workaround
			"U":        1.00, // Unavailable
			notDefined: 1.00, // Not Defined
		},
		"RC": { // Report Confidence
			"UC":       0.90, // Unconfirmed
			"UR":       0.95, // Uncorroborated
			"C":        1.00, // Confirmed
			notDefined: 1.00, // Not
		},

		// environmental metrics
		"CDP": { // Collateral Damage Potential
			"N":        0.0, // None
			"L":        0.1, // Low
			"LM":       0.3, // Low-Medium
			"MH":       0.4, // Medium-High
			"H":        0.5, // High
			notDefined: 0.0, // Not Defined
		},
		"TD": { // Target Distribution
			"N":        0.00, // None
			"L":        0.25, // Low
			"M":        0.75, // Medium
			"H":        1.00, // High
			notDefined: 1.00, // Not Defined
		},
		"CR": { // Confidentiality Requirement
			"L":        0.50, // Low
			"M":        1.00, // Medium
			"H":        1.51, // High
			notDefined: 1.00, // Not Defined
		},
		"IR": { // Integrity Requirement
			"L":        0.50, // Low
			"M":        1.00, // Medium
			"H":        1.51, // High
			notDefined: 1.00, // Not Defined
		},
		"AR": { // Availability Requirement
			"L":        0.50, // Low
			"M":        1.00, // Medium
			"H":        1.51, // High
			notDefined: 1.00, // Not Defined
		},
	}

	baseMetricsWeights = []string{"AV", "AC", "Au", "C", "I", "A"}
)

type Vector struct {
	common.Metrics
}

func NewVector() Vector {
	return Vector{common.NewMetrics(weights, notDefined)}
}

func (v Vector) Validate() error {
	for _, metric := range baseMetricsWeights {
		if _, err := v.Get(metric); err != nil {
			return fmt.Errorf("base vector: metric %q not defined", metric)
		}
	}
	return nil
}

// Override parse because it can contain parenthesis

func (v Vector) Parse(str string) error {
	return v.Metrics.Parse(strings.Trim(str, "()"))
}
