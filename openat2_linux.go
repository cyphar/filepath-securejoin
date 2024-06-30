//go:build linux

// Copyright (C) 2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	hasOpenat2Bool bool
	hasOpenat2Once sync.Once

	testForceHasOpenat2 *bool
)

func hasOpenat2() bool {
	if testForceHasOpenat2 != nil {
		return *testForceHasOpenat2
	}
	hasOpenat2Once.Do(func() {
		fd, err := unix.Openat2(unix.AT_FDCWD, ".", &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_IN_ROOT,
		})
		if err == nil {
			hasOpenat2Bool = true
			_ = unix.Close(fd)
		}
	})
	return hasOpenat2Bool
}

func isScopedLookup(how *unix.OpenHow) bool {
	return how.Resolve&(unix.RESOLVE_IN_ROOT|unix.RESOLVE_BENEATH) != 0
}

const scopedLookupMaxRetries = 10

func openat2File(dir *os.File, path string, how *unix.OpenHow) (*os.File, error) {
	fullPath := dir.Name() + "/" + path
	// Make sure we always set O_CLOEXEC.
	how.Flags |= unix.O_CLOEXEC
	var tries int
	for tries < scopedLookupMaxRetries {
		fd, err := unix.Openat2(int(dir.Fd()), path, how)
		if err != nil {
			// RESOLVE_IN_ROOT (and RESOLVE_BENEATH) can return -EAGAIN if we
			// resolve ".." while a mount or rename occurs anywhere on the
			// system. This could happen spuriously, or as the result of an
			// attacker trying to mess with us during lookup.
			//
			// We retry a couple of times to avoid the spurious errors, and if
			// we are being attacked then returning -EAGAIN is the best we can
			// do.
			if err == unix.EAGAIN && isScopedLookup(how) {
				tries++
				continue
			}
			return nil, &os.PathError{Op: "openat2", Path: fullPath, Err: err}
		}
		// If we are using RESOLVE_IN_ROOT, the name we generated may be wrong.
		// NOTE: The procRoot code MUST NOT use RESOLVE_IN_ROOT, otherwise
		//       you'll get infinite recursion here.
		if how.Resolve&unix.RESOLVE_IN_ROOT == unix.RESOLVE_IN_ROOT {
			if actualPath, err := rawProcSelfFdReadlink(fd); err == nil {
				fullPath = actualPath
			}
		}
		return os.NewFile(uintptr(fd), fullPath), nil
	}
	return nil, &os.PathError{Op: "openat2", Path: fullPath, Err: unix.EAGAIN}
}

// partialLookupOpenat2 is an alternative implementation of
// partialLookupInRoot, using openat2(RESOLVE_IN_ROOT) to more safely get a
// handle to the deepest existing child of the requested path within the root.
func partialLookupOpenat2(root *os.File, unsafePath string, unsafeHallucinateDirectories bool) (*os.File, string, error) {
	unsafePath = filepath.ToSlash(unsafePath) // noop

	if !hasOpenat2() {
		return nil, "", fmt.Errorf("openat2: %w", unix.ENOTSUP)
	}

	// TODO: Implement this as a git-bisect-like binary search.

	var hallucinateDirectoryTries int
	endIdx := len(unsafePath)
	for endIdx > 0 {
		subpath := unsafePath[:endIdx]

		var err error
		handle, err := openat2File(root, subpath, &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
		})
		if err == nil {
			// We found a subpath!
			remainingPath := unsafePath[endIdx:]
			// If we were asked to "hallucinate" non-existent paths as though
			// they are directories, take the remainingPath and clean it so
			// that any ".." components that would lead us back to real paths
			// can get resolved.
			if remainingPath != "" && unsafeHallucinateDirectories {
				if newRemainingPath := filepath.Clean(remainingPath); newRemainingPath != remainingPath {
					hallucinateDirectoryTries++
					if hallucinateDirectoryTries > maxUnsafeHallucinateDirectoryTries {
						return nil, "", fmt.Errorf("%w: trying to reconcile non-existent subpath %q", errTooManyFakeDirectories, remainingPath)
					}
					// Start the lookup from the end again using the new
					// remaining path.
					unsafePath = subpath + "/" + newRemainingPath
					endIdx = len(unsafePath)
					continue
				}
			}
			return handle, remainingPath, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, "", fmt.Errorf("open subpath: %w", err)
		}

		// That path doesn't exist, let's try the next directory up.
		endIdx = strings.LastIndexByte(subpath, '/')
	}
	// If we couldn't open anything, the whole subpath is missing. Return a
	// copy of the root fd so that the caller doesn't close this one by
	// accident.
	rootClone, err := dupFile(root)
	if err != nil {
		return nil, "", err
	}
	return rootClone, unsafePath, nil
}
