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
	"unsafe"

	"github.com/jokLiu/nvdtools/wfn"
)

const cacheEvictPercentage = 0.1 // every eviction cycle invalidates this part of cache size at once

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

// cachedCVEs stores cached CVEs, a channel to signal if the value is ready
type cachedCVEs struct {
	res           []MatchResult
	ready         chan struct{}
	size          int
	evictionIndex int // position in eviction queue
}

// updateResSize calculates the size of cached MatchResult and assigns it to cves.size
func (cves *cachedCVEs) updateResSize(key string) {
	cves.size = int(unsafe.Sizeof(key)) + len(key)
	if cves == nil {
		return
	}
	cves.size += int(unsafe.Sizeof(cves.res))
	for i := range cves.res {
		cves.size += int(unsafe.Sizeof(cves.res[i].CVE)) + len(cves.res[i].CVE)
		for _, attr := range cves.res[i].CPEs {
			cves.size += len(attr.Part) + int(unsafe.Sizeof(attr.Part))
			cves.size += len(attr.Vendor) + int(unsafe.Sizeof(attr.Vendor))
			cves.size += len(attr.Product) + int(unsafe.Sizeof(attr.Product))
			cves.size += len(attr.Version) + int(unsafe.Sizeof(attr.Version))
			cves.size += len(attr.Update) + int(unsafe.Sizeof(attr.Update))
			cves.size += len(attr.Edition) + int(unsafe.Sizeof(attr.Edition))
			cves.size += len(attr.SWEdition) + int(unsafe.Sizeof(attr.SWEdition))
			cves.size += len(attr.TargetHW) + int(unsafe.Sizeof(attr.TargetHW))
			cves.size += len(attr.Other) + int(unsafe.Sizeof(attr.Other))
			cves.size += len(attr.Language) + int(unsafe.Sizeof(attr.Language))
		}
	}
}

// Cache caches CVEs for known CPEs
type Cache struct {
	data           map[string]*cachedCVEs
	evictionQ      *evictionQueue
	mu             sync.Mutex
	Dict           Dictionary
	Idx            Index
	RequireVersion bool // ignore matching specifications that have Version == ANY
	MaxSize        int  // maximum size of the cache, 0 -- unlimited, -1 -- no caching
	size           int  // current size of the cache
}

// NewCache creates new Cache instance with dictionary dict.
func NewCache(dict Dictionary) *Cache {
	return &Cache{Dict: dict, evictionQ: new(evictionQueue)}
}

// SetRequireVersion sets if the instance of cache fails matching the dictionary
// records without Version attribute of CPE name.
// Returns a pointer to the instance of Cache, for easy chaining.
func (c *Cache) SetRequireVersion(requireVersion bool) *Cache {
	c.RequireVersion = requireVersion
	return c
}

// SetMaxSize sets maximum size of the cache to some pre-defined value,
// size of 0 disables eviction (makes the cache grow indefinitely),
// negative size disables caching.
// Returns a pointer to the instance of Cache, for easy chaining.
func (c *Cache) SetMaxSize(size int) *Cache {
	c.MaxSize = size
	return c
}

// Get returns slice of CVEs for CPE names from cpes parameter;
// if CVEs aren't cached (and the feature is enabled) it finds them in cveDict and caches the results
func (c *Cache) Get(cpes []*wfn.Attributes) []MatchResult {
	// negative max size of the cache disables caching
	if c.MaxSize < 0 {
		if c.Idx == nil {
			return c.match(cpes, c.Dict)
		}
		return c.match(cpes, c.dictFromIndex(cpes))
	}

	// otherwise, let's get to the business
	key := cacheKey(cpes)
	c.mu.Lock()
	if c.data == nil {
		c.data = make(map[string]*cachedCVEs)
	}
	cves := c.data[key]
	if cves != nil {
		// value is being computed, wait till ready
		c.mu.Unlock()
		<-cves.ready
		c.mu.Lock() // TODO: XXX: ugly, consider using atomic.Value instead
		cves.evictionIndex = c.evictionQ.touch(cves.evictionIndex)
		c.mu.Unlock()
		return cves.res
	}
	// first request; the goroutine that sent it computes the value
	cves = &cachedCVEs{ready: make(chan struct{})}
	c.data[key] = cves
	c.mu.Unlock()
	// now other requests for same key wait on the channel, and the requests for the different keys aren't blocked
	if c.Idx == nil {
		cves.res = c.match(cpes, c.Dict)
	} else {
		cves.res = c.match(cpes, c.dictFromIndex(cpes))
	}
	cves.updateResSize(key)
	c.mu.Lock()
	c.size += cves.size
	if c.MaxSize != 0 && c.size > c.MaxSize {
		c.evict(int(cacheEvictPercentage * float64(c.MaxSize)))
	}
	cves.evictionIndex = c.evictionQ.push(key)
	c.mu.Unlock()
	close(cves.ready)
	return cves.res
}

// dictFromIndex creates CVE dictionary from entries indexed by CPE names
func (c *Cache) dictFromIndex(cpes []*wfn.Attributes) Dictionary {
	if c.Idx == nil {
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
		if _, ok := c.Idx[product]; !ok {
			continue
		}
		for _, e := range c.Idx[product] {
			if _, ok := knownEntries[e]; ok {
				continue
			}
			knownEntries[e] = true
			d = append(d, e)
		}
	}
	for _, e := range c.Idx[wfn.Any] {
		if _, ok := knownEntries[e]; ok {
			continue
		}
		knownEntries[e] = true
		d = append(d, e)
	}
	return d
}

// match matches the CPE names against internal vulnerability dictionary and returns a slice of matching resutls
func (c *Cache) match(cpes []*wfn.Attributes, dict Dictionary) (result []MatchResult) {
	for _, v := range dict {
		if mm, ok := Match(cpes, v.Config(), c.RequireVersion); ok {
			mm = uniq(mm)
			result = append(result, MatchResult{v.CVEID(), mm})
		}
	}
	return result
}

// evict the least recently used records untile nbytes of capacity is achieved or no more records left.
// It is not concurrency-safe, c.mu should be locked before calling it.
func (c *Cache) evict(nbytes int) {
	for c.size+nbytes > c.MaxSize {
		key := c.evictionQ.pop()
		cd, ok := c.data[key]
		if !ok { // should not happen
			panic("attempted to evict non-existent record")
		}
		c.size -= cd.size
		delete(c.data, key)
	}
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
