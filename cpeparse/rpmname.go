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

	"github.com/jokLiu/nvdtools/wfn"
)

// FieldsFromRPMName returns name, version, release and acrhitecture parsed from RPM package name
func FieldsFromRPMName(s string) (name, ver, rel, arch string, err error) {
	pkg := s
	// extension
	if strings.HasSuffix(pkg, ".rpm") {
		pkg = pkg[:len(pkg)-4]
	}
	// architecture
	if i := strings.LastIndexByte(pkg, '.'); i != -1 {
		if arch, err = wfn.WFNize(pkg[i+1:]); err != nil {
			err = fmt.Errorf("couldn't parse architecture from RPM package name %q: %v", s, err)
			return
		}
		if arch == "noarch" || arch == "src" {
			arch = wfn.Any
		}
		pkg = pkg[:i]
	}
	// release
	if i := strings.LastIndexByte(pkg, '-'); i != -1 {
		if rel, err = wfn.WFNize(pkg[i+1:]); err != nil {
			err = fmt.Errorf("couldn't parse release from RPM package name %q: %v", s, err)
			return
		}
		pkg = pkg[:i]
	}
	// version
	if i := strings.LastIndexByte(pkg, '-'); i != -1 {
		if ver, err = wfn.WFNize(pkg[i+1:]); err != nil {
			err = fmt.Errorf("couldn't parse version from RPM package name %q: %v", s, err)
			return
		}
		pkg = pkg[:i]
	}
	// epoch -- we don't use it
	i := strings.IndexByte(pkg, ':')
	// name
	if name, err = wfn.WFNize(strings.ToLower(pkg[i+1:])); err != nil {
		err = fmt.Errorf("couldn't parse name from RPM package name %q", s)
		return
	}
	return
}

// FromRPMName parses CPE name from RPM package name
func FromRPMName(s string) (*wfn.Attributes, error) {
	var err error
	name, ver, rel, arch, err := FieldsFromRPMName(s)
	if err != nil {
		return nil, err
	}
	if name == wfn.Any {
		return nil, fmt.Errorf("no name found in RPM name %q", s)
	}
	if ver == wfn.Any {
		return nil, fmt.Errorf("no version found in RPM name %q", s)
	}
	return &wfn.Attributes{
		Part:     "a", // TODO: figure out the way to properly detect os packages (linux_kernel or smth)
		Product:  name,
		Version:  ver,
		Update:   rel,
		TargetHW: arch,
	}, nil
}
