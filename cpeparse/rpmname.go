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

package cpeparse

import (
	"fmt"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
)

// split a string into two parts based on given index
func split(s string, idx int) (left, right string) {
	return s[:idx], s[idx+1:]
}

// FieldsFromRPMName returns name, version, release and acrhitecture parsed from RPM package name
// NEVRA: https://blog.jasonantman.com/2014/07/how-yum-and-rpm-compare-versions/
func FieldsFromRPMName(pkg string) (name, epoch, version, release, arch string, err error) {
	// pkg should be name-(epoch:)version-release.arch.rpm

	// extension
	if strings.HasSuffix(pkg, ".rpm") {
		pkg = pkg[:len(pkg)-4]
	}

	var i int

	// name
	if i = strings.IndexByte(pkg, '-'); i == -1 {
		err = fmt.Errorf("can't split %q on '-' to find a name", pkg)
		return
	}
	name, pkg = split(pkg, i)
	name = strings.ToLower(name)

	// epoch? and version
	if i = strings.IndexByte(pkg, '-'); i == -1 {
		err = fmt.Errorf("can't split %q on '-' to find a version", pkg)
		return
	}
	version, pkg = split(pkg, i)
	if i = strings.IndexByte(version, ':'); i != -1 {
		epoch, version = split(version, i)
	}

	// release and arch
	if i = strings.IndexByte(pkg, '.'); i == -1 {
		err = fmt.Errorf("can't split %q on '-' to find release", pkg)
		return
	}
	release, arch = split(pkg, i)
	if arch == "src" || arch == "noarch" {
		arch = wfn.Any
	}

	return
}

// FromRPMName parses CPE name from RPM package name
func FromRPMName(attr *wfn.Attributes, s string) error {
	var err error
	name, _, ver, rel, arch, err := FieldsFromRPMName(s)
	if err != nil {
		return fmt.Errorf("can't get fields from %q: %v", s, err)
	}

	for n, addr := range map[string]*string{
		"name":    &name,
		"version": &ver,
		"release": &rel,
		"arch":    &arch,
	} {
		if *addr, err = wfn.WFNize(*addr); err != nil {
			err = fmt.Errorf("couldn't wfnize %s %q: %v", n, *addr, err)
		}
	}

	if name == wfn.Any {
		return fmt.Errorf("no name found in RPM name %q", s)
	}
	if ver == wfn.Any {
		return fmt.Errorf("no version found in RPM name %q", s)
	}
	attr.Part = "a" // TODO: figure out the way to properly detect os packages (linux_kernel or smth)
	attr.Product = name
	attr.Version = ver
	attr.Update = rel
	attr.TargetHW = arch
	return nil
}
