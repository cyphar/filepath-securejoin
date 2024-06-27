//go:build linux

// Copyright (C) 2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func testMkdirAll_Basic(t *testing.T, mkdirAll func(t *testing.T, root, unsafePath string, mode int) error) {
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
		// Symlink loop.
		"dir loop",
		"symlink loop/link ../loop/link",
	}

	withWithoutOpenat2(t, func(t *testing.T) {
		for name, test := range map[string]struct {
			unsafePath  string
			expectedErr error
		}{
			"existing":              {unsafePath: "a"},
			"basic":                 {unsafePath: "a/b/c/d/e/f/g/h/i/j"},
			"dotdot-in-nonexisting": {unsafePath: "a/b/c/d/e/f/g/h/i/j/k/../lmnop", expectedErr: unix.ENOENT},
			"dotdot-in-existing":    {unsafePath: "b/c/../c/./d/e/f/g/h"},
			"dotdot-after-symlink":  {unsafePath: "e/../dd/ee/ff"},
			// Check that trying to create under a file fails.
			"nondir-trailing":         {unsafePath: "b/c/file", expectedErr: unix.ENOTDIR},
			"nondir-dotdot":           {unsafePath: "b/c/file/../d", expectedErr: unix.ENOTDIR},
			"nondir-subdir":           {unsafePath: "b/c/file/subdir", expectedErr: unix.ENOTDIR},
			"nondir-symlink-trailing": {unsafePath: "b-file", expectedErr: unix.ENOTDIR},
			"nondir-symlink-dotdot":   {unsafePath: "b-file/../d", expectedErr: unix.ENOTDIR},
			"nondir-symlink-subdir":   {unsafePath: "b-file/subdir", expectedErr: unix.ENOTDIR},
			// Dangling symlinks are not followed.
			"dangling1-trailing": {unsafePath: "a-fake1", expectedErr: unix.EEXIST},
			"dangling1-basic":    {unsafePath: "a-fake1/foo", expectedErr: unix.EEXIST},
			"dangling1-dotdot":   {unsafePath: "a-fake1/../bar/baz", expectedErr: unix.ENOENT},
			"dangling2-trailing": {unsafePath: "a-fake2", expectedErr: unix.EEXIST},
			"dangling2-basic":    {unsafePath: "a-fake2/foo", expectedErr: unix.EEXIST},
			"dangling2-dotdot":   {unsafePath: "a-fake2/../bar/baz", expectedErr: unix.ENOENT},
			"dangling3-trailing": {unsafePath: "a-fake3", expectedErr: unix.EEXIST},
			"dangling3-basic":    {unsafePath: "a-fake3/foo", expectedErr: unix.EEXIST},
			"dangling3-dotdot":   {unsafePath: "a-fake3/../bar/baz", expectedErr: unix.ENOENT},
			// Non-lexical symlinks should work.
			"nonlexical-basic":           {unsafePath: "target/foo"},
			"nonlexical-level1-abs":      {unsafePath: "link1/target_abs/foo"},
			"nonlexical-level1-rel":      {unsafePath: "link1/target_rel/foo"},
			"nonlexical-level2-abs-abs":  {unsafePath: "link2/link1_abs/target_abs/foo"},
			"nonlexical-level2-abs-rel":  {unsafePath: "link2/link1_abs/target_rel/foo"},
			"nonlexical-level2-abs-open": {unsafePath: "link2/link1_abs/../target/foo"},
			"nonlexical-level2-rel-abs":  {unsafePath: "link2/link1_rel/target_abs/foo"},
			"nonlexical-level2-rel-rel":  {unsafePath: "link2/link1_rel/target_rel/foo"},
			"nonlexical-level2-rel-open": {unsafePath: "link2/link1_rel/../target/foo"},
			"nonlexical-level3-abs":      {unsafePath: "link3/target_abs/foo"},
			"nonlexical-level3-rel":      {unsafePath: "link3/target_rel/foo"},
			// But really tricky dangling symlinks should fail.
			"dangling-tricky1-trailing": {unsafePath: "link3/deep_dangling1", expectedErr: unix.EEXIST},
			"dangling-tricky1-basic":    {unsafePath: "link3/deep_dangling1/foo", expectedErr: unix.EEXIST},
			"dangling-tricky1-dotdot":   {unsafePath: "link3/deep_dangling1/../bar", expectedErr: unix.ENOENT},
			"dangling-tricky2-trailing": {unsafePath: "link3/deep_dangling2", expectedErr: unix.EEXIST},
			"dangling-tricky2-basic":    {unsafePath: "link3/deep_dangling2/foo", expectedErr: unix.EEXIST},
			"dangling-tricky2-dotdot":   {unsafePath: "link3/deep_dangling2/../bar", expectedErr: unix.ENOENT},
			// And trying to mkdir inside a loop should fail.
			"loop-trailing": {unsafePath: "loop/link", expectedErr: unix.ELOOP},
			"loop-basic":    {unsafePath: "loop/link/foo", expectedErr: unix.ELOOP},
			"loop-dotdot":   {unsafePath: "loop/link/../foo", expectedErr: unix.ELOOP},
		} {
			test := test // copy iterator
			t.Run(name, func(t *testing.T) {
				root := createTree(t, tree...)

				rootDir, err := os.OpenFile(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
				require.NoError(t, err)
				defer rootDir.Close()

				// Before trying to make the tree, figure out what
				// components don't exist yet so we can check them later.
				handle, remainingPath, err := partialLookupInRoot(rootDir, test.unsafePath)
				handleName := "<nil>"
				if handle != nil {
					handleName = handle.Name()
					defer handle.Close()
				}
				defer func() {
					if t.Failed() {
						t.Logf("partialLookupInRoot(%s, %s) -> (<%s>, %s, %v)", root, test.unsafePath, handleName, remainingPath, err)
					}
				}()

				// This mode is different to the one set up by createTree.
				const expectedMode = 0o711

				// Actually make the tree.
				err = mkdirAll(t, root, test.unsafePath, 0o711)
				assert.ErrorIsf(t, err, test.expectedErr, "MkdirAll(%q, %q)", root, test.unsafePath)

				remainingPath = filepath.Join("/", remainingPath)
				for remainingPath != filepath.Dir(remainingPath) {
					stat, err := fstatatFile(handle, "./"+remainingPath, unix.AT_SYMLINK_NOFOLLOW)
					if test.expectedErr == nil {
						// Check that the new components have the right
						// mode.
						if assert.NoErrorf(t, err, "unexpected error when checking new directory %q", remainingPath) {
							assert.Equalf(t, uint32(unix.S_IFDIR|expectedMode), stat.Mode, "new directory %q has the wrong mode", remainingPath)
						}
					} else {
						// Check that none of the components are
						// directories (i.e. make sure that the MkdirAll
						// was a no-op).
						if err == nil {
							assert.NotEqualf(t, uint32(unix.S_IFDIR), stat.Mode&unix.S_IFMT, "failed MkdirAll created a new directory at %q", remainingPath)
						}
					}
					// Jump up a level.
					remainingPath = filepath.Dir(remainingPath)
				}
			})
		}
	})
}

func TestMkdirAll_Basic(t *testing.T) {
	testMkdirAll_Basic(t, func(t *testing.T, root, unsafePath string, mode int) error {
		// We can't check expectedPath here.
		return MkdirAll(root, unsafePath, mode)
	})
}

func TestMkdirAllHandle_Basic(t *testing.T) {
	testMkdirAll_Basic(t, func(t *testing.T, root, unsafePath string, mode int) error {
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

		// We can use SecureJoin here becuase we aren't being attacked in this
		// particular test. Obviously this check is bogus for actual programs.
		expectedPath, err := SecureJoin(root, unsafePath)
		require.NoError(t, err)

		// Now double-check that the handle is correct.
		gotPath, err := procSelfFdReadlink(handle)
		require.NoError(t, err, "get real path of returned handle")
		assert.Equal(t, expectedPath, gotPath, "wrong final path from MkdirAllHandle")
		// Also check that the f.Name() is correct while we're at it (this is
		// not always guaranteed but it's better to try at least).
		assert.Equal(t, expectedPath, handle.Name(), "handle from MkdirAllHandle has the wrong .Name()")
		return nil
	})
}

func testMkdirAll_InvalidMode(t *testing.T, mkdirAll func(t *testing.T, root, unsafePath string, mode int) error) {
	for _, test := range []struct {
		mode        int
		expectedErr error
	}{
		// os.FileMode bits are invalid.
		{int(os.ModeDir | 0o777), errInvalidMode},
		{int(os.ModeSticky | 0o777), errInvalidMode},
		{int(os.ModeIrregular | 0o777), errInvalidMode},
		// unix.S_IFMT bits are also invalid.
		{unix.S_IFDIR | 0o777, errInvalidMode},
		{unix.S_IFREG | 0o777, errInvalidMode},
		{unix.S_IFIFO | 0o777, errInvalidMode},
		// suid/sgid bits are valid but you get an error because they don't get
		// applied by mkdirat.
		// TODO: Figure out if we want to allow this.
		{unix.S_ISUID | 0o777, errPossibleAttack},
		{unix.S_ISGID | 0o777, errPossibleAttack},
		{unix.S_ISUID | unix.S_ISGID | unix.S_ISVTX | 0o777, errPossibleAttack},
		// Proper sticky bit should work.
		{unix.S_ISVTX | 0o777, nil},
		// Regular mode bits.
		{0o777, nil},
		{0o711, nil},
	} {
		root := t.TempDir()
		err := mkdirAll(t, root, "a/b/c", test.mode)
		assert.ErrorIsf(t, err, test.expectedErr, "mkdirall 0o%.3o", test.mode)
	}
}

func TestMkdirAll_InvalidMode(t *testing.T) {
	testMkdirAll_InvalidMode(t, func(t *testing.T, root, unsafePath string, mode int) error {
		return MkdirAll(root, unsafePath, mode)
	})
}

func TestMkdirAllHandle_InvalidMode(t *testing.T) {
	testMkdirAll_InvalidMode(t, func(t *testing.T, root, unsafePath string, mode int) error {
		rootDir, err := os.OpenFile(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer rootDir.Close()
		handle, err := MkdirAllHandle(rootDir, unsafePath, mode)
		if err != nil {
			return err
		}
		_ = handle.Close()
		return nil
	})
}
