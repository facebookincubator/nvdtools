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
	if m, err := StrToMetrics(str); err != nil {
		t.Errorf("should be able to parse A:B/C:D")
	} else if !reflect.DeepEqual(m, expected) {
		t.Errorf("parsed %s incorrectly, expecting %q, got %q", str, expected, m)
	}

	str = "A:B/C"
	if _, err := StrToMetrics(str); err == nil {
		t.Errorf("shouldn't be able to parse %q", str)
	}

	str = "A:B/A:C"
	if _, err := StrToMetrics(str); err == nil {
		t.Errorf("should fail when provided multiple values for the same metric")
	}
}
