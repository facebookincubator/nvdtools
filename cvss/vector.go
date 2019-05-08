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

package cvss

import (
	"github.com/facebookincubator/nvdtools/cvss/v2"
	"github.com/facebookincubator/nvdtools/cvss/v3"
)

// Vector provides an interface for dealing with CVSS v2 and v3 vectors
type Vector interface {
	// Get returns a value associated with given metric or an error if it can't be resolved
	Get(metric string) (string, error)
	// Set associates the given value with a metric, error is returned if it can't be done
	Set(metric string, value string) error
	// String representation of the vector
	String() string
	// Parse will parse another vector into it overriding existing values
	Parse(string) error
	// Validate will check whether the vector is properly constructed, should be called before calculating the score
	Validate() error
	// Score will calculate vector's score
	Score() float64
}

func NewVectorV2() Vector {
	return v2.NewVector()
}

func NewVectorV3() Vector {
	return v3.NewVector()
}

// Severity represents scores severity
type Severity int

const (
	SeverityNone Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityNone:
		return "None"
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityCritical:
		return "Critical"
	default:
		panic("undefined severity")
	}
}

// SeverityFromScore will return the severity assigned to given score
func SeverityFromScore(score float64) Severity {
	if score <= 0 {
		return SeverityNone
	}
	if 0 < score && score < 4 {
		return SeverityLow
	}
	if 4 <= score && score < 7 {
		return SeverityMedium
	}
	if 7 <= score && score < 9 {
		return SeverityHigh
	}
	return SeverityCritical
}
