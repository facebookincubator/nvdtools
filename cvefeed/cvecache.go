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

package cvefeed

import (
	"bytes"
	"sort"
	"sync"

	"github.com/facebookincubator/nvdtools/wfn"
)

// Index maps the CPEs to the entries in the NVD feed they mentioned in
type Index map[string][]CVEItem

// NewIndex creates new Index from a slice of CVE entries
func NewIndex(d Dictionary) Index {
	idx := Index{}
	for _, entry := range d {
		set := map[string]bool{}
		for _, cpe := range collectCPEs(entry.Config()) {
			// Can happen, for instance, when the feed contains illegal binding of CPE name. Unfortunately, it happens to NVD,
			// e.g. embedded ? in cpe:2.3:a:disney:where\\'s_my_perry?_free:1.5.1:*:*:*:*:android:*:* of CVE-2014-5606
			if cpe == nil {
				continue
			}
			product := cpe.Product
			if product == wfn.Any || wfn.HasWildcard(product) {
				set[wfn.Any] = true
				continue
			}
			set[product] = true
		}
		for product := range set {
			idx[product] = append(idx[product], entry)
		}
	}
	return idx
}

func collectCPEs(dict []LogicalTest) (cpes []*wfn.Attributes) {
	for _, d := range dict {
		for _, cpe := range d.CPEs() {
			cpes = append(cpes, cpe)
		}
		if children := d.InnerTests(); len(children) != 0 {
			cpes = append(cpes, collectCPEs(children)...)
		}
	}
	return cpes
}

// MatchResult stores CVE and a slice of CPEs that matched it
type MatchResult struct {
	CVE  string
	CPEs []*wfn.Attributes
}

// cachedCVEs stores cached CVEs + a channel to signal if the value is ready
type cachedCVEs struct {
	res   []MatchResult
	ready chan struct{}
}

// Cache caches CVEs for known CPEs
type Cache struct {
	data           map[string]*cachedCVEs
	mu             sync.Mutex
	Dict           Dictionary
	Idx            Index
	requireVersion bool // ignore matching specifications that have Version == ANY
}

// NewCache creates new Cache instance with dictionary dict
func NewCache(dict Dictionary, requireVersion bool) *Cache {
	return &Cache{
		Dict:           dict,
		requireVersion: requireVersion,
	}
}

// Get returns slice of CVEs for CPE names from cpes parameter; if CVEs aren't cached
// if finds them in cveDict and caches the results
func (vc *Cache) Get(cpes []*wfn.Attributes) []MatchResult {
	key := cacheKey(cpes)
	vc.mu.Lock()
	if vc.data == nil {
		vc.data = make(map[string]*cachedCVEs)
	}
	cves := vc.data[key]
	if cves == nil {
		// first request; the goroutine that sent it computes the value
		cves = &cachedCVEs{ready: make(chan struct{})}
		vc.data[key] = cves
		vc.mu.Unlock()
		// now other requests for this key wait on the channel, and the other requests aren't blocked
		if vc.Idx == nil {
			cves.res = vc.match(cpes, vc.Dict)
		} else {
			cves.res = vc.match(cpes, vc.dictFromIndex(cpes))
		}
		close(cves.ready)
	} else {
		// value is being computed, wait till ready
		vc.mu.Unlock()
		<-cves.ready
	}
	return cves.res
}

// dictFromIndex creates CVE dictionary from entries indexed by CPE names
func (vc *Cache) dictFromIndex(cpes []*wfn.Attributes) Dictionary {
	if vc.Idx == nil {
		return nil
	}
	d := Dictionary{}
	knownEntries := map[CVEItem]bool{}
	for _, cpe := range cpes {
		if cpe == nil { // should never happen
			panic("nil CPE in dictionary")
		}
		product := cpe.Product
		if product == wfn.Any {
			continue
		}
		if _, ok := vc.Idx[product]; !ok {
			continue
		}
		for _, e := range vc.Idx[product] {
			if _, ok := knownEntries[e]; ok {
				continue
			}
			knownEntries[e] = true
			d = append(d, e)
		}
	}
	for _, e := range vc.Idx[wfn.Any] {
		if _, ok := knownEntries[e]; ok {
			continue
		}
		knownEntries[e] = true
		d = append(d, e)
	}
	return d
}

// match matches the CPE names against internal vulnerability dictionary and returns a slice of matching resutls
func (vc *Cache) match(cpes []*wfn.Attributes, dict Dictionary) (result []MatchResult) {
	for _, v := range dict {
		if mm, ok := Match(cpes, v.Config(), vc.requireVersion); ok {
			mm = uniq(mm)
			result = append(result, MatchResult{v.CVEID(), mm})
		}
	}
	return result
}

func cacheKey(cpes []*wfn.Attributes) string {
	var out bytes.Buffer
	for _, cpe := range cpes {
		if cpe == nil {
			continue
		}
		out.WriteString(cpe.Part)
		out.WriteByte('^')
		out.WriteString(cpe.Vendor)
		out.WriteByte('^')
		out.WriteString(cpe.Product)
		out.WriteByte('^')
		out.WriteString(cpe.Version)
		out.WriteByte('^')
		out.WriteString(cpe.Update)
		out.WriteByte('^')
		out.WriteString(cpe.Edition)
		out.WriteByte('^')
		out.WriteString(cpe.SWEdition)
		out.WriteByte('^')
		out.WriteString(cpe.TargetSW)
		out.WriteByte('^')
		out.WriteString(cpe.TargetHW)
		out.WriteByte('^')
		out.WriteString(cpe.Other)
		out.WriteByte('^')
		out.WriteString(cpe.Language)
		out.WriteByte('#')
	}
	return out.String()
}

func uniq(nn []*wfn.Attributes) []*wfn.Attributes {
	if len(nn) == 0 {
		return nn
	}
	sort.Slice(nn, func(i, j int) bool {
		a, b := nn[i], nn[j]
		if b == nil {
			return false
		}
		return a == nil || a.Part < b.Part || a.Vendor < b.Vendor || a.Product < b.Product ||
			a.Version < b.Version || a.Update < b.Update || a.Edition < b.Edition ||
			a.SWEdition < b.SWEdition || a.TargetSW < b.TargetSW || a.TargetHW < b.TargetHW ||
			a.Other < b.Other || a.Language < b.Language
	})
	j := 1
	for i := 1; i < len(nn); i++ {
		if nn[i] != nn[i-1] {
			nn[j] = nn[i]
			j++
		}
	}
	return nn[:j]
}
