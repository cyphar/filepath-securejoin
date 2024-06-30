// Copyright (C) 2014-2015 Docker Inc & Go Authors. All rights reserved.
// Copyright (C) 2017-2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package securejoin is an implementation of the hopefully-soon-to-be-included
// SecureJoin helper that is meant to be part of the "path/filepath" package.
// The purpose of this project is to provide a PoC implementation to make the
// SecureJoin proposal (https://github.com/golang/go/issues/20126) more
// tangible.
package securejoin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const maxSymlinkLimit = 255

// IsNotExist tells you if err is an error that implies that either the path
// accessed does not exist (or path components don't exist). This is
// effectively a more broad version of os.IsNotExist.
func IsNotExist(err error) bool {
	// Check that it's not actually an ENOTDIR, which in some cases is a more
	// convoluted case of ENOENT (usually involving weird paths).
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ENOENT)
}

func legacySecureJoinVFS(root, unsafePath string, vfs VFS) (string, error) {
	// Use the os.* VFS implementation if none was specified.
	if vfs == nil {
		vfs = osVFS{}
	}

	unsafePath = filepath.FromSlash(unsafePath)
	var (
		currentPath   string
		remainingPath = unsafePath
		linksWalked   int
	)
	for remainingPath != "" {
		if v := filepath.VolumeName(remainingPath); v != "" {
			remainingPath = remainingPath[len(v):]
		}

		// Get the next path component.
		var part string
		if i := strings.IndexRune(remainingPath, filepath.Separator); i == -1 {
			part, remainingPath = remainingPath, ""
		} else {
			part, remainingPath = remainingPath[:i], remainingPath[i+1:]
		}

		// Apply the component lexically to the path we are building.
		// currentPath does not contain any symlinks, and we are lexically
		// dealing with a single component, so it's okay to do a filepath.Clean
		// here.
		nextPath := filepath.Join(string(filepath.Separator), currentPath, part)
		if nextPath == string(filepath.Separator) {
			currentPath = ""
			continue
		}
		fullPath := root + string(filepath.Separator) + nextPath

		// Figure out whether the path is a symlink.
		fi, err := vfs.Lstat(fullPath)
		if err != nil && !IsNotExist(err) {
			return "", err
		}
		// Treat non-existent path components the same as non-symlinks (we
		// can't do any better here).
		if IsNotExist(err) || fi.Mode()&os.ModeSymlink == 0 {
			currentPath = nextPath
			continue
		}

		// It's a symlink, so get its contents and expand it by prepending it
		// to the yet-unparsed path.
		linksWalked++
		if linksWalked > maxSymlinkLimit {
			return "", &os.PathError{Op: "SecureJoin", Path: root + string(filepath.Separator) + unsafePath, Err: syscall.ELOOP}
		}

		dest, err := vfs.Readlink(fullPath)
		if err != nil {
			return "", err
		}
		remainingPath = dest + string(filepath.Separator) + remainingPath
		// Absolute symlinks reset any work we've already done.
		if filepath.IsAbs(dest) {
			currentPath = ""
		}
	}

	// There should be no lexical components like ".." left in the path here,
	// but for safety clean up the path before joining it to the root.
	finalPath := filepath.Join(string(filepath.Separator), currentPath)
	return filepath.Join(root, finalPath), nil
}
