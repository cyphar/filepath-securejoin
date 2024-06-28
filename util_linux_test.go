//go:build linux

// Copyright (C) 2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func requireRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test requires root")
	}
}

func withWithoutOpenat2(t *testing.T, testFn func(t *testing.T)) {
	t.Run("openat2=auto", testFn)

	for _, useOpenat2 := range []bool{true, false} {
		useOpenat2 := useOpenat2 // copy iterator
		t.Run(fmt.Sprintf("openat2=%v", useOpenat2), func(t *testing.T) {
			if useOpenat2 && !hasOpenat2() {
				t.Skip("no openat2 support")
			}
			testingForceHasOpenat2 = &useOpenat2
			defer func() { testingForceHasOpenat2 = nil }()

			testFn(t)
		})
	}
}

func testForceGetProcRoot(t *testing.T, testFn func(t *testing.T, expectOvermounts bool)) {
	for _, test := range []struct {
		name             string
		forceGetProcRoot forceGetProcRootLevel
		expectOvermounts bool
	}{
		{`procfd="fsopen()"`, forceGetProcRootDefault, false},
		{`procfd="open_tree_clone"`, forceGetProcRootOpenTree, false},
		{`procfd="open_tree_clone(AT_RECURSIVE)"`, forceGetProcRootOpenTreeAtRecursive, true},
		{`procfd="open()"`, forceGetProcRootUnsafe, true},
	} {
		test := test // copy iterator
		t.Run(test.name, func(t *testing.T) {
			testingForceGetProcRoot = &test.forceGetProcRoot
			defer func() { testingForceGetProcRoot = nil }()

			testFn(t, test.expectOvermounts)
		})
	}
}

func testForceProcThreadSelf(t *testing.T, testFn func(t *testing.T)) {
	for _, test := range []struct {
		name                string
		forceProcThreadSelf forceProcThreadSelfLevel
	}{
		{`thread-self="thread-self"`, forceProcThreadSelfDefault},
		{`thread-self="self/task"`, forceProcSelfTask},
		{`thread-self="self"`, forceProcSelf},
	} {
		test := test // copy iterator
		t.Run(test.name, func(t *testing.T) {
			testingForceProcThreadSelf = &test.forceProcThreadSelf
			defer func() { testingForceProcThreadSelf = nil }()

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
	inoType, subPath, f := f[0], f[1], f[2:]
	fullPath := filepath.Join(root, subPath)
	switch inoType {
	case "dir":
		err := os.MkdirAll(fullPath, 0o755)
		require.NoError(t, err)
	case "file":
		var contents []byte
		if len(f) >= 1 {
			contents = []byte(f[0])
		}
		err := os.WriteFile(fullPath, contents, 0o644)
		require.NoError(t, err)
	case "symlink":
		if len(f) < 1 {
			t.Fatalf("invalid spec %q", spec)
		}
		target := f[0]
		err := os.Symlink(target, fullPath)
		require.NoError(t, err)
	}
}

func createTree(t *testing.T, specs ...string) string {
	root := t.TempDir()

	// Put the root in a subdir.
	treeRoot := filepath.Join(root, "tree")
	os.MkdirAll(treeRoot, 0o755)

	for _, spec := range specs {
		createInTree(t, treeRoot, spec)
	}
	return treeRoot
}