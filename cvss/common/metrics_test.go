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

package common

import (
	"reflect"
	"testing"
)

func TestStrToMetrics(t *testing.T) {
	str := "A:B/C:D"
	expected := Metrics{"A": "B", "C": "D"}
	if m, err := strToMetrics(str); err != nil {
		t.Errorf("should be able to parse A:B/C:D")
	} else if !reflect.DeepEqual(m, expected) {
		t.Errorf("parsed %s incorrectly, expecting %q, got %q", str, expected, m)
	}

	str = "A:B/C"
	if _, err := strToMetrics(str); err == nil {
		t.Errorf("shouldn't be able to parse %q", str)
	}

	str = "A:B/A:C"
	if _, err := strToMetrics(str); err == nil {
		t.Errorf("should fail when provided multiple values for the same metric")
	}
}

func TestMetrics(t *testing.T) {
	metrics, _ := strToMetrics("A:B/C:D")
	if b, err := metrics.Get("A"); err != nil || b != "B" {
		t.Errorf("metrics.Get(A) != B")
	}
	if d, err := metrics.Get("C"); err != nil || d != "D" {
		t.Errorf("metrics.Get(C) != D")
	}
	if metrics.Set("X", "Y") != nil {
		t.Errorf("can't set metric X to Y")
	}
}

func TestWeightsMetrics(t *testing.T) {
	weights := map[string]map[string]float64{"A": {"B": 1, "C": 2}}
	wms := WeightsMetrics{make(Metrics), weights}

	// test set
	if wms.Set("A", "B") != nil {
		t.Errorf("should be able to set valid metric to valid value")
	}
	if wms.Set("A", "D") == nil {
		t.Errorf("shouldn't be able to set valid metric to invalid value")
	}
	if wms.Set("B", "ANY") == nil {
		t.Errorf("shouldn't be able to set invalid metric")
	}

	// test parse
	if wms.Parse("A:C") != nil {
		t.Errorf("should be able to parse valid metric and value")
	}
	if c, err := wms.Get("A"); err != nil || c != "C" {
		t.Errorf("incorrectlly parsed metric A, should have value C")
	}

	// test Weights
	if w, err := wms.Weight("A"); err != nil || w != 2 {
		t.Errorf("incorrect weight returned for metric A, should be 2 (C)")
	}
	if _, err := wms.Weight("B"); err == nil {
		t.Errorf("should return an error on invalid metric")
	}
}
