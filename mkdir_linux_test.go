//go:build linux

// Copyright (C) 2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"errors"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func testMkdirAllBasic(t *testing.T, mkdirAll func(t *testing.T, root, unsafePath string, mode os.FileMode) error) {
	// We create a new tree for each test, but the template is the same.
	tree := []string{
		"dir a",
		"dir b/c/d/e/f",
		"file b/c/file",
		"symlink e /b/c/d/e",
		"symlink b-file b/c/file",
		// Dangling symlinks.
		"symlink a-fake1 a/fake",
		"symlink a-fake2 a/fake/foo/bar/..",
		"symlink a-fake3 a/fake/../../b",
		// Test non-lexical symlinks.
		"dir target",
		"dir link1",
		"symlink link1/target_abs /target",
		"symlink link1/target_rel ../target",
		"dir link2",
		"symlink link2/link1_abs /link1",
		"symlink link2/link1_rel ../link1",
		"dir link3",
		"symlink link3/target_abs /link2/link1_rel/target_rel",
		"symlink link3/target_rel ../link2/link1_rel/target_rel",
		"symlink link3/deep_dangling1 ../link2/link1_rel/target_rel/nonexist",
		"symlink link3/deep_dangling2 ../link2/link1_rel/target_rel/nonexist",
	}

	withWithoutOpenat2(t, func(t *testing.T) {
		for _, test := range []struct {
			unsafePath  string
			expectedErr error
		}{
			{unsafePath: "a"},
			{unsafePath: "a/b/c/d/e/f/g/h/i/j/k/../lmnop"},
			{unsafePath: "b/c/../c/./d/e/f/g/h"},
			{unsafePath: "e/../dd/ee/ff"},
			// Check that trying to create under a file fails.
			{unsafePath: "b/c/file", expectedErr: unix.ENOTDIR},
			{unsafePath: "b/c/file/../d", expectedErr: unix.ENOTDIR},
			{unsafePath: "b/c/file/subdir", expectedErr: unix.ENOTDIR},
			{unsafePath: "b-file", expectedErr: unix.ENOTDIR},
			{unsafePath: "b-file/../d", expectedErr: unix.ENOTDIR},
			{unsafePath: "b-file/subdir", expectedErr: unix.ENOTDIR},
			// Dangling symlinks are followed.
			{unsafePath: "a-fake1", expectedErr: unix.EEXIST},
			{unsafePath: "a-fake1/foo", expectedErr: unix.EEXIST},
			{unsafePath: "a-fake1/foo/bar/baz", expectedErr: unix.EEXIST},
			{unsafePath: "a-fake2", expectedErr: unix.EEXIST},
			{unsafePath: "a-fake2/foo", expectedErr: unix.EEXIST},
			{unsafePath: "a-fake2/foo/bar/baz", expectedErr: unix.EEXIST},
			{unsafePath: "a-fake3", expectedErr: unix.EEXIST},
			{unsafePath: "a-fake3/foo", expectedErr: unix.EEXIST},
			{unsafePath: "a-fake3/foo/bar/baz", expectedErr: unix.EEXIST},
			// Non-lexical symlinks should work.
			{unsafePath: "target/foo"},
			{unsafePath: "link1/target_abs/foo"},
			{unsafePath: "link1/target_rel/foo"},
			{unsafePath: "link2/link1_abs/target_abs/foo"},
			{unsafePath: "link2/link1_abs/target_rel/foo"},
			{unsafePath: "link2/link1_abs/../target/foo"},
			{unsafePath: "link2/link1_rel/target_abs/foo"},
			{unsafePath: "link2/link1_rel/target_rel/foo"},
			{unsafePath: "link2/link1_rel/../target/foo"},
			{unsafePath: "link3/target_abs/foo"},
			{unsafePath: "link3/target_rel/foo"},
			// But really tricky dangling symlinks should fail.
			{unsafePath: "link3/deep_dangling1/foo", expectedErr: unix.EEXIST},
			{unsafePath: "link3/deep_dangling2/foo", expectedErr: unix.EEXIST},
		} {
			test := test // copy iterator
			t.Run(test.unsafePath, func(t *testing.T) {
				root := createTree(t, tree...)

				rootDir, err := os.OpenFile(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
				require.Nil(t, err)
				defer rootDir.Close()

				// Before trying to make the tree, figure out what
				// components don't exist yet so we can check them later.
				handle, remainingPath, err := partialLookupInRoot(rootDir, test.unsafePath)
				handleName := "<nil>"
				if handle != nil {
					handleName = handle.Name()
				}
				t.Logf("partialLookupInRoot(%s, %s) -> (<%s>, %s, %v)", root, test.unsafePath, handleName, remainingPath, err)

				// This mode is different to the one set up by createTree.
				const expectedMode = 0o711

				// Actually make the tree.
				err = mkdirAll(t, root, test.unsafePath, 0o711)
				if err != test.expectedErr && !errors.Is(err, test.expectedErr) {
					t.Errorf("MkdirAll(%q, %q) produced an unexpected error: %v != %v", root, test.unsafePath, test.expectedErr, err)
				}

				remainingPath = path.Join("/", remainingPath)
				for remainingPath != path.Dir(remainingPath) {
					stat, err := fstatatFile(handle, "./"+remainingPath, unix.AT_SYMLINK_NOFOLLOW)
					if test.expectedErr == nil {
						// Check that the new components have the right
						// mode.
						if err != nil {
							t.Errorf("unexpected error when checking new directory %q: %v", remainingPath, err)
						} else if stat.Mode&^unix.S_IFMT != expectedMode {
							t.Errorf("new directory %q has the wrong mode (0o%.3o != 0o%.3o)", remainingPath, expectedMode, stat.Mode)
						}
					} else {
						// Check that none of the components are
						// directories (i.e. make sure that the MkdirAll
						// was a no-op).
						if err == nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR {
							t.Errorf("failed MkdirAll created a new directory at %q", remainingPath)
						}
					}
					// Jump up a level.
					remainingPath = path.Dir(remainingPath)
				}
			})
		}
	})
}

func TestMkdirAllBasic(t *testing.T) {
	testMkdirAllBasic(t, func(t *testing.T, root, unsafePath string, mode os.FileMode) error {
		// We can't check expectedPath here.
		return MkdirAll(root, unsafePath, mode)
	})
}

func TestMkdirAllHandleBasic(t *testing.T) {
	testMkdirAllBasic(t, func(t *testing.T, root, unsafePath string, mode os.FileMode) error {
		// We can use SecureJoin here becuase we aren't being attacked in this
		// particular test. Obviously this check is bogus for actual programs.
		expectedPath, err := SecureJoin(root, unsafePath)
		require.Nil(t, err)

		// Same logic as MkdirAll.
		rootDir, err := os.OpenFile(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer rootDir.Close()
		handle, err := MkdirAllHandle(rootDir, unsafePath, mode)
		if err != nil {
			return err
		}
		defer handle.Close()

		// Now double-check that the handle is correct.
		gotPath, err := procSelfFdReadlink(handle)
		require.Nil(t, err, "get real path of returned handle")
		if expectedPath != gotPath {
			t.Errorf("MkdirAllHandle(%q, %q) is the wrong path: %q != %q", root, unsafePath, expectedPath, gotPath)
		}

		// Also check that the f.Name() is correct while we're at it (this is
		// not always guaranteed but it's better to try at least).
		if expectedPath != handle.Name() {
			t.Errorf("MkdirAllHandle(%q, %q) has incorrect Name: %q != %q", root, unsafePath, expectedPath, handle.Name())
		}
		return nil
	})
}
