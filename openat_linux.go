// SPDX-License-Identifier: MPL-2.0

//go:build linux

// Copyright (C) 2024-2025 Aleksa Sarai <cyphar@cyphar.com>
// Copyright (C) 2024-2025 SUSE LLC
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package securejoin

import (
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

func dupFile(f *os.File) (*os.File, error) {
	fd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, os.NewSyscallError("fcntl(F_DUPFD_CLOEXEC)", err)
	}
	return os.NewFile(uintptr(fd), f.Name()), nil
}

// prepareAtWith returns -EBADF (an invalid fd) if dir is nil, otherwise using
// the dir.Fd(). We use -EBADF because in filepath-securejoin we generally
// don't want to allow relative-to-cwd paths. The returned path is an
// *informational* string that describes a reasonable pathname for the given
// *at(2) arguments. You must not use the full path for any actual filesystem
// operations.
func prepareAt(dir *os.File, path string) (dirFd int, unsafeUnmaskedPath string) {
	dirFd, dirPath := -int(unix.EBADF), "."
	if dir != nil {
		dirFd, dirPath = int(dir.Fd()), dir.Name()
	}
	if !filepath.IsAbs(path) {
		// only prepend the dirfd path for relative paths
		path = dirPath + "/" + path
	}
	// NOTE: If path is "." or "", the returned path won't be filepath.Clean,
	// but that's okay since this path is either used for errors (in which case
	// a trailing "/" or "/." is important information) or will be
	// filepath.Clean'd later (in the case of openatFile).
	return dirFd, path
}

func openatFile(dir *os.File, path string, flags int, mode int) (*os.File, error) { //nolint:unparam // wrapper func
	dirFd, fullPath := prepareAt(dir, path)
	// Make sure we always set O_CLOEXEC.
	flags |= unix.O_CLOEXEC
	fd, err := unix.Openat(dirFd, path, flags, uint32(mode))
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: fullPath, Err: err}
	}
	runtime.KeepAlive(dir)
	// openat is only used with lexically-safe paths so we can use
	// filepath.Clean here, and also the path itself is not going to be used
	// for actual path operations.
	fullPath = filepath.Clean(fullPath)
	return os.NewFile(uintptr(fd), fullPath), nil
}

func fstatatFile(dir *os.File, path string, flags int) (unix.Stat_t, error) {
	dirFd, fullPath := prepareAt(dir, path)
	var stat unix.Stat_t
	if err := unix.Fstatat(dirFd, path, &stat, flags); err != nil {
		return stat, &os.PathError{Op: "fstatat", Path: fullPath, Err: err}
	}
	runtime.KeepAlive(dir)
	return stat, nil
}

func readlinkatFile(dir *os.File, path string) (string, error) {
	dirFd, fullPath := prepareAt(dir, path)
	size := 4096
	for {
		linkBuf := make([]byte, size)
		n, err := unix.Readlinkat(dirFd, path, linkBuf)
		if err != nil {
			return "", &os.PathError{Op: "readlinkat", Path: fullPath, Err: err}
		}
		runtime.KeepAlive(dir)
		if n != size {
			return string(linkBuf[:n]), nil
		}
		// Possible truncation, resize the buffer.
		size *= 2
	}
}
