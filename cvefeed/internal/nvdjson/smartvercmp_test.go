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

package nvdjson

import (
	"fmt"
	"testing"
)

func TestSmartVerCmp(t *testing.T) {
	cases := []struct {
		v1, v2 string
		ret    int
	}{
		{"1.0", "1.0", 0},
		{"1.0.1", "1.0", 1},
		{"1.0.14", "1.0.4", 1},
		{"95SE", "98SP1", -1},
		{"16.0.0", "3.2.7", 1},
		{"10.23", "10.21", 1},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%q vs %q", c.v1, c.v2), func(t *testing.T) {
			if ret := smartVerCmp(c.v1, c.v2); ret != c.ret {
				t.Fatalf("expected %d, got %d", ret, c.ret)
			}
		})
	}
}
