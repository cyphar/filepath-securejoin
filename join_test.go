// SPDX-License-Identifier: BSD-3-Clause

// Copyright (C) 2017-2025 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: These tests won't work on plan9 because it doesn't have symlinks, and
//       also we use '/' here explicitly which probably won't work on Windows.

type input struct {
	root, unsafe string
	expected     string
}

// In a path without symlinks, SecureJoin is equivalent to Clean+Join.
func TestNoSymlink(t *testing.T) {
	dir := t.TempDir()

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
		if err != nil {
			t.Errorf("securejoin(%q, %q): unexpected error: %v", test.root, test.unsafe, err)
		}
		if got != test.expected {
			t.Errorf("securejoin(%q, %q): expected %q, got %q", test.root, test.unsafe, test.expected, got)
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
		if got != test.expected {
			t.Errorf("IsNotExist(%#v): expected %v, got %v", test.err, test.expected, got)
		}
	}
}

func TestUncleanRoot(t *testing.T) {
	root := t.TempDir()

	for _, test := range []struct {
		testName, root string
		expectedErr    error
	}{
		{"trailing-dotdot", "foo/..", errUnsafeRoot},
		{"leading-dotdot", "../foo", errUnsafeRoot},
		{"middle-dotdot", "../foo", errUnsafeRoot},
		{"many-dotdot", "foo/../foo/../a", errUnsafeRoot},
		{"trailing-slash", root + "/foo/bar/", nil},
		{"trailing-slashes", root + "/foo/bar///", nil},
		{"many-slashes", root + "/foo///bar////baz", nil},
		{"plain-dot", root + "/foo/./bar", nil},
		{"many-dot", root + "/foo/./bar/./.", nil},
		{"unclean-safe", root + "/foo///./bar/.///.///", nil},
		{"unclean-unsafe", root + "/foo///./bar/..///.///", errUnsafeRoot},
	} {
		test := test // copy iterator
		t.Run(test.testName, func(t *testing.T) {
			_, err := SecureJoin(test.root, "foo/bar/baz")
			if test.expectedErr != nil {
				assert.ErrorIsf(t, err, test.expectedErr, "SecureJoin with unsafe root %q", test.root)
			} else {
				assert.NoErrorf(t, err, "SecureJoin with safe but unclean root %q", test.root)
			}
		})
	}
}

func TestHasDotDot(t *testing.T) {
	for _, test := range []struct {
		testName, path string
		expected       bool
	}{
		{"plain-dotdot", "..", true},
		{"trailing-dotdot", "foo/bar/baz/..", true},
		{"leading-dotdot", "../foo/bar/baz", true},
		{"middle-dotdot", "foo/bar/../baz", true},
		{"dotdot-in-name1", "foo/..bar/baz", false},
		{"dotdot-in-name2", "foo/bar../baz", false},
		{"dotdot-in-name3", "foo/b..r/baz", false},
		{"dotdot-in-name4", "..foo/bar/baz", false},
		{"dotdot-in-name5", "foo/bar/baz..", false},
		{"dot1", "./foo/bar/baz", false},
		{"dot2", "foo/bar/baz/.", false},
		{"dot3", "foo/././bar/baz", false},
		{"unclean", "foo//.//bar/baz////", false},
	} {
		test := test // copy iterator
		t.Run(test.testName, func(t *testing.T) {
			got := hasDotDot(test.path)
			assert.Equalf(t, test.expected, got, "unexpected result for hasDotDot(%q)", test.path)
		})
	}
}
