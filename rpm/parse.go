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
	"strings"
)

// Package represents one RPM package
type Package struct {
	Name string
	Label
	Arch string
}

// Label is part of the package and allows us to commpare two RPM packages
type Label struct {
	Epoch   string
	Version string
	Release string
}

// FieldsFromRPMName returns name, version, release and architecture parsed from RPM package name
// NEVRA: https://blog.jasonantman.com/2014/07/how-yum-and-rpm-compare-versions/
func Parse(pkg string) (*Package, error) {
	// pkg should be name-(epoch:)version[-release].arch.rpm

	// extension
	if strings.HasSuffix(pkg, ".rpm") {
		pkg = pkg[:len(pkg)-4]
	}

	var p Package

	// name
	if parts := strings.SplitN(pkg, "-", 2); len(parts) == 2 {
		p.Name, pkg = strings.ToLower(parts[0]), parts[1]
	} else {
		return nil, fmt.Errorf("can't split %q on '-' to find a name", pkg)
	}

	// arch
	if i := strings.LastIndexByte(pkg, '.'); i >= 0 {
		pkg, p.Arch = pkg[:i], pkg[i+1:]
		if p.Arch == "src" || p.Arch == "noarch" {
			p.Arch = ""
		}
	} else {
		return nil, fmt.Errorf("can't find arch in pkg %q", pkg)
	}

	// label = [epoch:]version[-release]

	// check if there's epoch
	if parts := strings.SplitN(pkg, ":", 2); len(parts) == 2 {
		p.Label.Epoch, pkg = parts[0], parts[1]
	}

	// check if there's release
	if parts := strings.SplitN(pkg, "-", 2); len(parts) == 2 {
		pkg, p.Label.Release = parts[0], parts[1]
	}
	p.Label.Version = pkg

	return &p, nil
}
