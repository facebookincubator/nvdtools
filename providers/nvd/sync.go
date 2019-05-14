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

package nvd

import (
	"context"
	"os"
)

// Syncer is an abstract interface for data feed synchronizers.
type Syncer interface {
	Sync(ctx context.Context, src SourceConfig, localdir string) error
}

// Sync provides full synchronization between remote and local data feeds.
type Sync struct {
	Feeds    []Syncer
	Source   *SourceConfig
	LocalDir string
}

// Do executes the synchronization.
func (s Sync) Do(ctx context.Context) error {
	err := os.MkdirAll(s.LocalDir, 0755)
	if err != nil {
		return err
	}
	src := s.Source
	if src == nil {
		src = NewSourceConfig()
	}
	vsrc := *src
	for _, feed := range s.Feeds {
		if err = feed.Sync(ctx, vsrc, s.LocalDir); err != nil {
			return err
		}
	}
	return nil
}
