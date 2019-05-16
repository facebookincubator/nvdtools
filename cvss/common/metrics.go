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

package common

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

const (
	partSeparator   = "/"
	metricSeparator = ":"
)

// parse A:B/C:D into map{A:B, C:D}
func strToMap(str string) (map[string]string, error) {
	metrics := make(map[string]string)
	for _, part := range strings.Split(str, partSeparator) {
		tmp := strings.Split(part, metricSeparator)
		if len(tmp) != 2 {
			return nil, fmt.Errorf("need two values separated by %s, got %q", metricSeparator, part)
		}
		if _, exists := metrics[tmp[0]]; exists {
			return nil, fmt.Errorf("metric %q already set", tmp[0])
		}
		metrics[tmp[0]] = tmp[1]
	}
	return metrics, nil
}

// Metrics holds metric values. Weights are used to validate values as well as to do parsing
type Metrics struct {
	metrics   map[string]string
	weights   map[string]map[string]float64
	undefined string
}

func NewMetrics(weights map[string]map[string]float64, undefined string) Metrics {
	return Metrics{
		metrics:   make(map[string]string),
		weights:   weights,
		undefined: undefined,
	}
}

func (ms Metrics) Get(m string) (string, error) {
	if value, ok := ms.metrics[m]; ok {
		return value, nil
	}
	if values, ok := ms.weights[m]; ok {
		if _, ok := values[ms.undefined]; ok {
			return ms.undefined, nil
		}
	}
	return "", fmt.Errorf("metric %q not defined", m)
}

func (ms Metrics) Set(metric string, value string) error {
	values, ok := ms.weights[metric]
	if !ok {
		return fmt.Errorf("metric %q not defined for vector", metric)
	}
	if _, ok = values[value]; !ok {
		return fmt.Errorf("can't set metric %q to %q", metric, value)
	}
	ms.metrics[metric] = value
	return nil
}

func (ms Metrics) String() string {
	var parts []string
	for metric, value := range ms.metrics {
		if value != ms.undefined {
			parts = append(parts, fmt.Sprintf("%s%s%s", metric, metricSeparator, value))
		}
	}
	return strings.Join(parts, partSeparator)
}

func (ms Metrics) Parse(str string) error {
	metrics, err := strToMap(str)
	if err != nil {
		return errors.Wrapf(err, "unable to parse metrics")
	}
	for metric, value := range metrics {
		if value != ms.undefined {
			if err = ms.Set(metric, value); err != nil {
				return errors.Wrapf(err, "unable to set metric %q to %q", metric, value)
			}
		}
	}
	return nil
}

// weight functions

// Weight will return the weight for given metric.
// If metric is not set, try to return weight as if metric wasn't defined
// if there's not weight fo undefined, return an error
func (ms Metrics) Weight(metric string) (float64, error) {
	if value, err := ms.Get(metric); err == nil {
		return ms.weights[metric][value], nil
	}
	if w, ok := ms.weights[metric][ms.undefined]; ok {
		return w, nil
	}
	return 0, fmt.Errorf("weight for %s not set and does not allow undefined values", metric)
}

// WeightMust does the same as Weight, but panics if error gets returned
func (ms Metrics) WeightMust(metric string) float64 {
	w, err := ms.Weight(metric)
	if err != nil {
		panic(err)
	}
	return w
}
