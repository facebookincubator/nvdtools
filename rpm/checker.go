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

package rpm

import (
	"fmt"

	"github.com/facebookincubator/nvdtools/wfn"
)

// Checker knows how to verify whether some package has been fixed or not
type Checker interface {
	// Check should return whether a given package on distribution is fixed for some CVE
	Check(pkg *Package, distro *wfn.Attributes, cve string) bool
}

// CheckAny returns a Checker which will return true if any of the underlying checkers returns true
func CheckAny(chks ...Checker) Checker {
	return anyChecker(chks)
}

type anyChecker []Checker

// Check is part of the Checker interface
func (c anyChecker) Check(pkg *Package, distro *wfn.Attributes, cve string) bool {
	for _, chk := range c {
		if chk.Check(pkg, distro, cve) {
			return true
		}
	}
	return false
}

// CheckAll returns a Checker which will return true if all of the underlying checkers returns true
func CheckAll(chks ...Checker) Checker {
	return allChecker(chks)
}

type allChecker []Checker

// Check is part of the Checker interface
func (c allChecker) Check(pkg *Package, distro *wfn.Attributes, cve string) bool {
	if len(c) == 0 {
		return false
	}
	for _, chk := range c {
		if !chk.Check(pkg, distro, cve) {
			return false
		}
	}
	return true
}

// MapChecker implements the Checker interface
// calls the checker which is mapped to checked CVE
type MapChecker map[string]Checker // CVE -> Checker

// Check is part of the Checker interface
func (c MapChecker) Check(pkg *Package, distro *wfn.Attributes, cve string) bool {
	if chk, ok := c[cve]; ok {
		return chk.Check(pkg, distro, cve)
	}
	return false
}

// Check will parse package and distro and call given checker to return
func Check(chk Checker, pkg, distro, cve string) (bool, error) {
	p, err := Parse(pkg)
	if err != nil {
		return false, fmt.Errorf("can't parse package %q: %v", pkg, err)
	}

	d, err := wfn.Parse(distro)
	if err != nil {
		return false, fmt.Errorf("can't parse distro cpe %q: %v", distro, err)
	}

	return chk.Check(p, d, cve), nil
}
