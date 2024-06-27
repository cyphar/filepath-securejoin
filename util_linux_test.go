//go:build linux

// Copyright (C) 2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func withWithoutOpenat2(t *testing.T, testFn func(t *testing.T)) {
	for _, useOpenat2 := range []bool{true, false} {
		useOpenat2 := useOpenat2 // copy iterator
		t.Run(fmt.Sprintf("openat2=%v", useOpenat2), func(t *testing.T) {
			if useOpenat2 && !hasOpenat2() {
				t.Skip("no openat2 support")
			}
			testForceHasOpenat2 = &useOpenat2
			defer func() {
				testForceHasOpenat2 = nil
			}()

			testFn(t)
		})
	}
}

// Format:
//
//	dir <name>
//	file <name> <?content>
//	symlink <name> <target>
func createInTree(t *testing.T, root, spec string) {
	f := strings.Fields(spec)
	if len(f) < 2 {
		t.Fatalf("invalid spec %q", spec)
	}
	fullPath := path.Join(root, f[1])
	switch f[0] {
	case "dir":
		err := os.MkdirAll(fullPath, 0o755)
		require.Nil(t, err)
	case "file":
		var contents []byte
		if len(f) >= 3 {
			contents = []byte(f[2])
		}
		err := os.WriteFile(fullPath, contents, 0o644)
		require.Nil(t, err)
	case "symlink":
		if len(f) < 3 {
			t.Fatalf("invalid spec %q", spec)
		}
		target := f[2]
		err := os.Symlink(target, fullPath)
		require.Nil(t, err)
	}
}

func createTree(t *testing.T, specs ...string) string {
	root := t.TempDir()
	for _, spec := range specs {
		createInTree(t, root, spec)
	}
	return root
}
