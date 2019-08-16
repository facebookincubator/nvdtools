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
	// pkg should be name-(epoch:)version-release.arch.rpm

	// extension
	if strings.HasSuffix(pkg, ".rpm") {
		pkg = pkg[:len(pkg)-4]
	}

	var p Package
	var parts []string

	// name
	if parts = strings.SplitN(pkg, "-", 2); len(parts) != 2 {
		return nil, fmt.Errorf("can't split %q on '-' to find a name", pkg)
	}
	p.Name, pkg = strings.ToLower(parts[0]), parts[1]

	// epoch? and version
	if parts = strings.SplitN(pkg, "-", 2); len(parts) != 2 {
		return nil, fmt.Errorf("can't split %q on '-' to find a version", pkg)
	}
	p.Label.Version, pkg = parts[0], parts[1]
	if parts = strings.SplitN(p.Label.Version, ":", 2); len(parts) == 2 {
		p.Label.Epoch, p.Label.Version = parts[0], parts[1]
	}

	// release and arch
	if parts = strings.SplitN(pkg, ".", 2); len(parts) != 2 {
		return nil, fmt.Errorf("can't split %q on '-' to find releakse", pkg)
	}
	p.Label.Release, p.Arch = parts[0], parts[1]
	if p.Arch == "src" || p.Arch == "noarch" {
		p.Arch = ""
	}

	return &p, nil
}
