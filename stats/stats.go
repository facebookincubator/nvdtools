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

package stats

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
)

var (
	// Global is the global stats object. It can be used when you only need one stats object between multiple modules in a program
	Global = New()
)

// Stats encapsulates functionallity of incrementing counters and incrementing values
type Stats struct {
	OutputFile   string
	LogToStderr  bool
	counters     map[string]int64
	countersLock sync.RWMutex
	values       map[string]float64
	valuesLock   sync.RWMutex
}

// New creates new Stats object
func New() *Stats {
	s := Stats{}
	s.Clear() // this will also initialize the maps
	return &s
}

// AddFlags adds configuration flags for a stats object
func (s *Stats) AddFlags() {
	flag.StringVar(&s.OutputFile, "output_stats", "", "output stats to this file")
	flag.BoolVar(&s.LogToStderr, "log_stats", false, "log stats to stderr")
}

// IncrementCounter increments the counter associated with the key by 1
func (s *Stats) IncrementCounter(key string) {
	s.IncrementCounterBy(key, 1)
}

// IncrementCounterBy increments the counter associated with the key by the given value
func (s *Stats) IncrementCounterBy(key string, value int64) {
	s.countersLock.Lock()
	s.counters[key] += value
	s.countersLock.Unlock()
}

// AddToValue adds to the value associated with the key
func (s *Stats) AddToValue(key string, value float64) {
	s.valuesLock.Lock()
	s.values[key] += value
	s.valuesLock.Unlock()
}

// GetCounter returns the count associated with the key
func (s *Stats) GetCounter(key string) int64 {
	s.countersLock.RLock()
	defer s.countersLock.RUnlock()
	return s.counters[key]
}

// GetValue returns the value associated with the key
func (s *Stats) GetValue(key string) float64 {
	s.valuesLock.RLock()
	defer s.valuesLock.RUnlock()
	return s.values[key]
}

// Clear will empty out the stats, all counters are set to 0, all values set to 0
func (s *Stats) Clear() {
	s.counters = make(map[string]int64)
	s.values = make(map[string]float64)
}

// Write will write all stats to stderr and/or a file. configured through stats.OutputFile and stats.sLogToStderr
func (s *Stats) Write() error {
	if s.LogToStderr {
		if err := s.write(os.Stderr); err != nil {
			return fmt.Errorf("failed to write stats to stderr: %v", err)
		}
	}
	if s.OutputFile != "" {
		f, err := os.OpenFile(s.OutputFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("failed to open stats file: %v", err)
		}
		defer f.Close()
		if err = s.write(f); err != nil {
			return fmt.Errorf("failed to write stats to file: %v", err)
		}
	}
	return nil
}

func (s *Stats) write(w io.Writer) (err error) {
	cw := csv.NewWriter(w)

	defer func() {
		cw.Flush()
		if err == nil {
			// don't override the existing error with possible flush error
			err = cw.Error()
		}
	}()

	for key, counter := range s.counters {
		record := []string{key, fmt.Sprintf("%d", counter)}
		if err = cw.Write(record); err != nil {
			return err
		}
	}

	for key, value := range s.values {
		record := []string{key, fmt.Sprintf("%.2f", value)}
		if err = cw.Write(record); err != nil {
			return err
		}
	}

	return nil
}
