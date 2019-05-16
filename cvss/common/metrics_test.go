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

func TestStrToMap(t *testing.T) {
	str := "A:B/C:D"
	expected := map[string]string{"A": "B", "C": "D"}
	if m, err := strToMap(str); err != nil {
		t.Errorf("should be able to parse A:B/C:D")
	} else if !reflect.DeepEqual(m, expected) {
		t.Errorf("parsed %s incorrectly, expecting %q, got %q", str, expected, m)
	}

	str = "A:B/C"
	if _, err := strToMap(str); err == nil {
		t.Errorf("shouldn't be able to parse %q", str)
	}

	str = "A:B/A:C"
	if _, err := strToMap(str); err == nil {
		t.Errorf("should fail when provided multiple values for the same metric")
	}

	metrics, _ := strToMap("A:B/C:D")
	if b, ok := metrics["A"]; !(ok && b == "B") {
		t.Errorf("metrics[A] != B")
	}
	if d, ok := metrics["C"]; !(ok && d == "D") {
		t.Errorf("metrics[C] != D")
	}
}

func TestMetrics(t *testing.T) {
	weights := map[string]map[string]float64{"A": {"B": 1, "C": 2, "X": 3}}
	ms := NewMetrics(weights, "X")

	if x, err := ms.Get("A"); err != nil || x != "X" {
		t.Errorf("value for A should be undefined X")
	}

	// test set
	if ms.Set("A", "B") != nil {
		t.Errorf("should be able to set valid metric to valid value")
	}
	if ms.Set("A", "D") == nil {
		t.Errorf("shouldn't be able to set valid metric to invalid value")
	}
	if ms.Set("B", "ANY") == nil {
		t.Errorf("shouldn't be able to set invalid metric")
	}

	// test parse
	if ms.Parse("A:C") != nil {
		t.Errorf("should be able to parse valid metric and value")
	}
	if c, err := ms.Get("A"); err != nil || c != "C" {
		t.Errorf("incorrectlly parsed metric A, should have value C")
	}

	// test Weights
	if w, err := ms.Weight("A"); err != nil || w != 2 {
		t.Errorf("incorrect weight returned for metric A, should be 2 (C)")
	}
	if _, err := ms.Weight("B"); err == nil {
		t.Errorf("should return an error on invalid metric")
	}

	if ms.Parse("A:X") != nil {
		t.Errorf("should be able to parse valid metric (undefined)")
	}
	if c, err := ms.Get("A"); err != nil || c != "C" {
		t.Errorf("incorrectlly parsed metric A, should have old value C, not be undefined")
	}
}
