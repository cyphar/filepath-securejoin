//go:build linux

// Copyright (C) 2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// MkdirAllHandle is equivalent to MkdirAll, except that it is safer to use in
// two respects:
//
//   - The caller provides the root directory as an *os.File (preferably O_PATH)
//     handle. This means that the caller can be sure which root directory is
//     being used. Note that this can be emulated by using /proc/self/fd/... as
//     the root path with MkdirAll.
//
//   - Once all of the directories have been created, an *os.File (O_PATH) handle
//     to the directory at unsafePath is returned to the caller. This is done in
//     an effectively-race-free way (an attacker would only be able to swap the
//     final directory component), which is not possible to emulate with
//     MkdirAll.
//
// In addition, the returned handle is obtained far more efficiently than doing
// a brand new lookup of unsafePath (such as with SecureJoin or openat2) after
// doing MkdirAll. If you intend to open the directory after creating it, you
// should use MkdirAllHandle.
func MkdirAllHandle(root *os.File, unsafePath string, mode os.FileMode) (_ *os.File, Err error) {
	// Try to open as much of the path as possible.
	currentDir, remainingPath, err := partialLookupInRoot(root, unsafePath)
	if err != nil {
		return nil, fmt.Errorf("find existing subpath of %q: %w", unsafePath, err)
	}
	defer func() {
		if Err != nil {
			_ = currentDir.Close()
		}
	}()

	// If there is an attacker deleting directories as we walk into them,
	// detect this proactively. Note this is guaranteed to detect if the
	// attacker deleted any part of the tree up to currentDir.
	//
	// Once we walk into a dead directory, partialLookupInRoot would not be
	// able to walk further down the tree (directories must be empty before
	// they are deleted), and if the attacker has removed the entire tree we
	// can be sure that anything that was originally inside a dead directory
	// must also be deleted and thus is a dead directory in its own right.
	//
	// This is mostly a quality-of-life check, because mkdir will simply fail
	// later if the attacker deletes the tree after this check.
	if err := isDeadInode(currentDir); err != nil {
		return nil, fmt.Errorf("finding existing subpath of %q: %w", unsafePath, err)
	}

	// The remaining path can be cleaned because none of the path components
	// exist and thus there are no symlinks to worry about (and removing ..
	// also removes the possibility of a parallel-write attack tricking us).
	remainingPath = path.Join("/", filepath.ToSlash(remainingPath))

	// Create the remaining components.
	for _, part := range strings.Split(remainingPath, "/") {
		switch part {
		case "":
			// Skip over no-op paths like "". This only happens if the
			// remaining path is empty.
			continue
		case ".", "..":
			// This should never happen, but especially in the case of .., make
			// sure we don't hit any of these special parts.
			return nil, fmt.Errorf("[internal error] remaining path contained unexpected component %q", part)
		}

		// NOTE: mkdir(2) will not follow trailing symlinks, so we can safely
		// create the finaly component without worrying about symlink-exchange
		// attacks.
		if err := unix.Mkdirat(int(currentDir.Fd()), part, uint32(mode)); err != nil {
			err = &os.PathError{Op: "mkdirat", Path: currentDir.Name() + "/" + part, Err: err}
			// Make the error a bit nicer if the directory is dead.
			if err2 := isDeadInode(currentDir); err2 != nil {
				err = fmt.Errorf("%w (%w)", err, err2)
			}
			return nil, err
		}

		// Get a handle to the next component.
		nextDir, err := openatFile(currentDir, part, unix.O_PATH|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		_ = currentDir.Close()
		currentDir = nextDir
	}
	return currentDir, nil
}

// MkdirAll is a race-safe alternative to the Go stdlib's os.MkdirAll function,
// where the new directory is guaranteed to be within the root directory (if an
// attacker can move directories from inside the root to outside the root, the
// created directory tree might be outside of the root but the key constraint
// is that at no point will we walk outside of the directory tree we are
// creating).
//
// Effectively, MkdirAll(root, unsafePath, mode) is equivalent to
//
//	path, _ := securejoin.SecureJoin(root, unsafePath)
//	err := os.MkdirAll(path, mode)
//
// But is much safer. The above implementation is unsafe because if an attacker
// can modify the filesystem tree between SecureJoin and MkdirAll, it is
// possible for MkdirAll to resolve unsafe symlink components and create
// directories outside of the root.
//
// If you plan to open the directory after you have created it or want to use
// an open directory handle as the root, you should use MkdirAllHandle instead.
// This function is a wrapper around MkdirAllHandle.
func MkdirAll(root, unsafePath string, mode os.FileMode) error {
	rootDir, err := os.OpenFile(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer rootDir.Close()

	f, err := MkdirAllHandle(rootDir, unsafePath, mode)
	if err != nil {
		return err
	}
	_ = f.Close()
	return nil
}
