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
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Dictionary is a slice of entries
type Dictionary = []CVEItem

// LoadXMLDictionary parses dictionary from multiple NVD vulenrability feed XML files
func LoadXMLDictionary(paths ...string) (Dictionary, error) {
	return loadDictionary(loadXMLFile, paths...)
}

// LoadJSONDictionary parses dictionary from multiple NVD vulenrability feed JSON files
func LoadJSONDictionary(paths ...string) (Dictionary, error) {
	return loadDictionary(loadJSONFile, paths...)
}

func loadDictionary(loadFunc func(string) (Dictionary, error), paths ...string) (Dictionary, error) {
	var dict Dictionary
	var wg sync.WaitGroup
	done := make(chan struct{})
	errDone := make(chan struct{})
	dictChan := make(chan Dictionary, 1)
	errChan := make(chan error, 1)
	for _, path := range paths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			feed, err := loadFunc(path)
			if err != nil {
				errChan <- fmt.Errorf("dictionary: failed to load feed %q: %v", path, err)
				return
			}
			dictChan <- feed
		}(path)
	}
	go func() {
		for d := range dictChan {
			dict = append(dict, d...)
		}
		close(done)
	}()
	var errs []string
	go func() {
		for e := range errChan {
			errs = append(errs, e.Error())
		}
		close(errDone)
	}()
	wg.Wait()
	close(dictChan)
	close(errChan)
	<-done
	<-errDone
	if len(errs) > 0 {
		return dict, errors.New(strings.Join(errs, "\n"))
	}
	return dict, nil
}

// loadXMLFile parses dictionary from NVD vulnerability feed XML file
func loadXMLFile(path string) (Dictionary, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("dictionary: failed to load feed %q: %v", path, err)
	}
	defer f.Close()
	return ParseXML(f)
}

// loadJSONFile parses dictionary from NVD vulnerability feed XML file
func loadJSONFile(path string) (Dictionary, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("dictionary: failed to load feed %q: %v", path, err)
	}
	defer f.Close()
	return ParseJSON(f)
}
