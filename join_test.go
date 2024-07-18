// Copyright (C) 2017-2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO: These tests won't work on plan9 because it doesn't have symlinks, and
//       also we use '/' here explicitly which probably won't work on Windows.

func symlink(t *testing.T, oldname, newname string) {
	err := os.Symlink(oldname, newname)
	require.NoError(t, err)
}

type input struct {
	root, unsafe string
	expected     string
}

// Test basic handling of symlink expansion.
func testSymlink(t *testing.T) {
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)

	symlink(t, "somepath", filepath.Join(dir, "etc"))
	symlink(t, "../../../../../../../../../../../../../etc", filepath.Join(dir, "etclink"))
	symlink(t, "/../../../../../../../../../../../../../etc/passwd", filepath.Join(dir, "passwd"))

	rootOrVol := string(filepath.Separator)
	if vol := filepath.VolumeName(dir); vol != "" {
		rootOrVol = vol + rootOrVol
	}

	tc := []input{
		// Make sure that expansion with a root of '/' proceeds in the expected fashion.
		{rootOrVol, filepath.Join(dir, "passwd"), filepath.Join(rootOrVol, "etc", "passwd")},
		{rootOrVol, filepath.Join(dir, "etclink"), filepath.Join(rootOrVol, "etc")},

		{rootOrVol, filepath.Join(dir, "etc"), filepath.Join(dir, "somepath")},
		// Now test scoped expansion.
		{dir, "passwd", filepath.Join(dir, "somepath", "passwd")},
		{dir, "etclink", filepath.Join(dir, "somepath")},
		{dir, "etc", filepath.Join(dir, "somepath")},
		{dir, "etc/test", filepath.Join(dir, "somepath", "test")},
		{dir, "etc/test/..", filepath.Join(dir, "somepath")},
	}

	for _, test := range tc {
		got, err := SecureJoin(test.root, test.unsafe)
		if !assert.NoErrorf(t, err, "securejoin(%q, %q)", test.root, test.unsafe) {
			continue
		}
		// This is only for OS X, where /etc is a symlink to /private/etc. In
		// principle, SecureJoin(/, pth) is the same as EvalSymlinks(pth) in
		// the case where the path exists.
		if test.root == "/" {
			if expected, err := filepath.EvalSymlinks(test.expected); err == nil {
				test.expected = expected
			}
		}
		assert.Equalf(t, test.expected, got, "securejoin(%q, %q)", test.root, test.unsafe)
	}
}

// In a path without symlinks, SecureJoin is equivalent to Clean+Join.
func TestNoSymlink(t *testing.T) {
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)

	tc := []input{
		{dir, "somepath", filepath.Join(dir, "somepath")},
		{dir, "even/more/path", filepath.Join(dir, "even", "more", "path")},
		{dir, "/this/is/a/path", filepath.Join(dir, "this", "is", "a", "path")},
		{dir, "also/a/../path/././/with/some/./.././junk", filepath.Join(dir, "also", "path", "with", "junk")},
		{dir, "yetanother/../path/././/with/some/./.././junk../../../../../../../../../../../../etc/passwd", filepath.Join(dir, "etc", "passwd")},
		{dir, "/../../../../../../../../../../../../../../../../etc/passwd", filepath.Join(dir, "etc", "passwd")},
		{dir, "../../../../../../../../../../../../../../../../somedir", filepath.Join(dir, "somedir")},
		{dir, "../../../../../../../../../../../../../../../../", filepath.Join(dir)},
		{dir, "./../../.././././../../../../../../../../../../../../../../../../etc passwd", filepath.Join(dir, "etc passwd")},
	}

	if runtime.GOOS == "windows" {
		tc = append(tc, []input{
			{dir, "d:\\etc\\test", filepath.Join(dir, "etc", "test")},
		}...)
	}

	for _, test := range tc {
		got, err := SecureJoin(test.root, test.unsafe)
		if assert.NoErrorf(t, err, "securejoin(%q, %q)", test.root, test.unsafe) {
			assert.Equalf(t, test.expected, got, "securejoin(%q, %q)", test.root, test.unsafe)
		}
	}
}

// Make sure that .. is **not** expanded lexically.
func TestNonLexical(t *testing.T) {
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)

	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
	os.MkdirAll(filepath.Join(dir, "cousinparent", "cousin"), 0755)
	symlink(t, "../cousinparent/cousin", filepath.Join(dir, "subdir", "link"))
	symlink(t, "/../cousinparent/cousin", filepath.Join(dir, "subdir", "link2"))
	symlink(t, "/../../../../../../../../../../../../../../../../cousinparent/cousin", filepath.Join(dir, "subdir", "link3"))

	for _, test := range []input{
		{dir, "subdir", filepath.Join(dir, "subdir")},
		{dir, "subdir/link/test", filepath.Join(dir, "cousinparent", "cousin", "test")},
		{dir, "subdir/link2/test", filepath.Join(dir, "cousinparent", "cousin", "test")},
		{dir, "subdir/link3/test", filepath.Join(dir, "cousinparent", "cousin", "test")},
		{dir, "subdir/../test", filepath.Join(dir, "test")},
		// This is the divergence from a simple filepath.Clean implementation.
		{dir, "subdir/link/../test", filepath.Join(dir, "cousinparent", "test")},
		{dir, "subdir/link2/../test", filepath.Join(dir, "cousinparent", "test")},
		{dir, "subdir/link3/../test", filepath.Join(dir, "cousinparent", "test")},
	} {
		got, err := SecureJoin(test.root, test.unsafe)
		if assert.NoErrorf(t, err, "securejoin(%q, %q)", test.root, test.unsafe) {
			assert.Equalf(t, test.expected, got, "securejoin(%q, %q)", test.root, test.unsafe)
		}
	}
}

// Make sure that symlink loops result in errors.
func TestSymlinkLoop(t *testing.T) {
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)

	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
	symlink(t, "../../../../../../../../../../../../../../../../path", filepath.Join(dir, "subdir", "link"))
	symlink(t, "/subdir/link", filepath.Join(dir, "path"))
	symlink(t, "/../../../../../../../../../../../../../../../../self", filepath.Join(dir, "self"))

	for _, test := range []struct {
		root, unsafe string
	}{
		{dir, "subdir/link"},
		{dir, "path"},
		{dir, "../../path"},
		{dir, "subdir/link/../.."},
		{dir, "../../../../../../../../../../../../../../../../subdir/link/../../../../../../../../../../../../../../../.."},
		{dir, "self"},
		{dir, "self/.."},
		{dir, "/../../../../../../../../../../../../../../../../self/.."},
		{dir, "/self/././.."},
	} {
		_, err := SecureJoin(test.root, test.unsafe)
		assert.ErrorIsf(t, err, syscall.ELOOP, "securejoin(%q, %q)", test.root, test.unsafe)
	}
}

// Make sure that ENOTDIR is correctly handled.
func TestEnotdir(t *testing.T) {
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)

	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
	ioutil.WriteFile(filepath.Join(dir, "notdir"), []byte("I am not a directory!"), 0755)
	symlink(t, "/../../../notdir/somechild", filepath.Join(dir, "subdir", "link"))

	for _, test := range []input{
		{dir, "subdir/link", filepath.Join(dir, "notdir/somechild")},
		{dir, "notdir", filepath.Join(dir, "notdir")},
		{dir, "notdir/child", filepath.Join(dir, "notdir/child")},
	} {
		got, err := SecureJoin(test.root, test.unsafe)
		if assert.NoErrorf(t, err, "securejoin(%q, %q)", test.root, test.unsafe) {
			assert.Equalf(t, test.expected, got, "securejoin(%q, %q)", test.root, test.unsafe)
		}
	}
}

// Some silly tests to make sure that all error types are correctly handled.
func TestIsNotExist(t *testing.T) {
	for _, test := range []struct {
		err      error
		expected bool
	}{
		{&os.PathError{Op: "test1", Err: syscall.ENOENT}, true},
		{&os.LinkError{Op: "test1", Err: syscall.ENOENT}, true},
		{&os.SyscallError{Syscall: "test1", Err: syscall.ENOENT}, true},
		{&os.PathError{Op: "test2", Err: syscall.ENOTDIR}, true},
		{&os.LinkError{Op: "test2", Err: syscall.ENOTDIR}, true},
		{&os.SyscallError{Syscall: "test2", Err: syscall.ENOTDIR}, true},
		{&os.PathError{Op: "test3", Err: syscall.EACCES}, false},
		{&os.LinkError{Op: "test3", Err: syscall.EACCES}, false},
		{&os.SyscallError{Syscall: "test3", Err: syscall.EACCES}, false},
		{errors.New("not a proper error"), false},
	} {
		got := IsNotExist(test.err)
		assert.Equalf(t, test.expected, got, "IsNotExist(%#v)", test.err)
	}
}

type mockVFS struct {
	lstat    func(path string) (os.FileInfo, error)
	readlink func(path string) (string, error)
}

func (m mockVFS) Lstat(path string) (os.FileInfo, error) { return m.lstat(path) }
func (m mockVFS) Readlink(path string) (string, error)   { return m.readlink(path) }

// Make sure that SecureJoinVFS actually does use the given VFS interface.
func TestSecureJoinVFS(t *testing.T) {
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)

	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
	os.MkdirAll(filepath.Join(dir, "cousinparent", "cousin"), 0755)
	symlink(t, "../cousinparent/cousin", filepath.Join(dir, "subdir", "link"))
	symlink(t, "/../cousinparent/cousin", filepath.Join(dir, "subdir", "link2"))
	symlink(t, "/../../../../../../../../../../../../../../../../cousinparent/cousin", filepath.Join(dir, "subdir", "link3"))

	for _, test := range []input{
		{dir, "subdir", filepath.Join(dir, "subdir")},
		{dir, "subdir/link/test", filepath.Join(dir, "cousinparent", "cousin", "test")},
		{dir, "subdir/link2/test", filepath.Join(dir, "cousinparent", "cousin", "test")},
		{dir, "subdir/link3/test", filepath.Join(dir, "cousinparent", "cousin", "test")},
		{dir, "subdir/../test", filepath.Join(dir, "test")},
		// This is the divergence from a simple filepath.Clean implementation.
		{dir, "subdir/link/../test", filepath.Join(dir, "cousinparent", "test")},
		{dir, "subdir/link2/../test", filepath.Join(dir, "cousinparent", "test")},
		{dir, "subdir/link3/../test", filepath.Join(dir, "cousinparent", "test")},
	} {
		var nLstat, nReadlink int
		mock := mockVFS{
			lstat:    func(path string) (os.FileInfo, error) { nLstat++; return os.Lstat(path) },
			readlink: func(path string) (string, error) { nReadlink++; return os.Readlink(path) },
		}

		got, err := SecureJoinVFS(test.root, test.unsafe, mock)
		if assert.NoErrorf(t, err, "securejoin(%q, %q)", test.root, test.unsafe) {
			assert.Equalf(t, test.expected, got, "securejoin(%q, %q)", test.root, test.unsafe)
			assert.Truef(t, nLstat+nReadlink > 0, "securejoin(%q, %q): expected either lstat or readlink to be called", test.root, test.unsafe)
		}
	}
}

// Make sure that SecureJoinVFS actually does use the given VFS interface, and
// that errors are correctly propagated.
func TestSecureJoinVFSErrors(t *testing.T) {
	var (
		fakeErr     = errors.New("FAKE ERROR")
		lstatErr    = fmt.Errorf("%w: lstat", fakeErr)
		readlinkErr = fmt.Errorf("%w: readlink", fakeErr)
	)

	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)

	// Make a link.
	symlink(t, "../../../../../../../../../../../../../../../../path", filepath.Join(dir, "link"))

	// Define some fake mock functions.
	lstatFailFn := func(path string) (os.FileInfo, error) { return nil, lstatErr }
	readlinkFailFn := func(path string) (string, error) { return "", readlinkErr }

	// Make sure that the set of {lstat, readlink} failures do propagate.
	for idx, test := range []struct {
		vfs       VFS
		expectErr bool
	}{
		{
			expectErr: false,
			vfs: mockVFS{
				lstat:    os.Lstat,
				readlink: os.Readlink,
			},
		},
		{
			expectErr: true,
			vfs: mockVFS{
				lstat:    lstatFailFn,
				readlink: os.Readlink,
			},
		},
		{
			expectErr: true,
			vfs: mockVFS{
				lstat:    os.Lstat,
				readlink: readlinkFailFn,
			},
		},
		{
			expectErr: true,
			vfs: mockVFS{
				lstat:    lstatFailFn,
				readlink: readlinkFailFn,
			},
		},
	} {
		_, err := SecureJoinVFS(dir, "link", test.vfs)
		if test.expectErr {
			assert.ErrorIsf(t, err, fakeErr, "SecureJoinVFS.mock%d", idx)
		} else {
			assert.NoErrorf(t, err, "SecureJoinVFS.mock%d", idx)
		}
	}
}
