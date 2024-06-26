//go:build linux

// Copyright (C) 2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// partialLookupInRoot tries to lookup as much of the request path as possible
// within the provided root (a-la RESOLVE_IN_ROOT) and opens the final existing
// component of the requested path, returning a file handle to the final
// existing component and a string containing the remaining path components.
func partialLookupInRoot(root *os.File, unsafePath string) (_ *os.File, _ string, Err error) {
	unsafePath = filepath.ToSlash(unsafePath) // noop

	// This is very similar to SecureJoin, except that we operate on the
	// components using file descriptors. We then return the last component we
	// managed open, along with the remaining path components not opened.

	// Try to use openat2 if possible.
	if hasOpenat2() {
		return partialLookupOpenat2(root, unsafePath)
	}

	// Get the "actual" root path from /proc/self/fd. This is necessary if the
	// root is some magic-link like /proc/$pid/root, in which case we want to
	// make sure when we do checkProcSelfFdPath that we are using the correct
	// root path.
	logicalRootPath, err := procSelfFdReadlink(root)
	if err != nil {
		return nil, "", fmt.Errorf("get real root path: %w", err)
	}

	currentDir, err := dupFile(root)
	if err != nil {
		return nil, "", fmt.Errorf("clone root fd: %w", err)
	}
	defer func() {
		if Err != nil {
			_ = currentDir.Close()
		}
	}()

	var (
		linksWalked   int
		currentPath   string
		remainingPath = unsafePath
	)
	for remainingPath != "" {
		// Save the current remaining path so if the part is not real we can
		// return the path including the component.
		oldRemainingPath := remainingPath

		// Get the next path component.
		var part string
		if i := strings.IndexByte(remainingPath, '/'); i == -1 {
			part, remainingPath = remainingPath, ""
		} else {
			part, remainingPath = remainingPath[:i], remainingPath[i+1:]
		}
		// Skip any "//" components.
		if part == "" {
			continue
		}

		// Apply the component lexically to the path we are building.
		// currentPath does not contain any symlinks, and we are lexically
		// dealing with a single component, so it's okay to do a filepath.Clean
		// here.
		nextPath := path.Join("/", currentPath, part)
		// If we hit the root, continue on without actually opening it.
		if nextPath == "/" {
			// Jump to root.
			rootClone, err := dupFile(root)
			if err != nil {
				return nil, "", fmt.Errorf("clone root fd: %w", err)
			}
			_ = currentDir.Close()
			currentDir = rootClone
			currentPath = nextPath
			continue
		}

		// Try to open the next component as a directory.
		nextDir, err := openatFile(currentDir, part, unix.O_PATH|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		switch {
		case err == nil:
			_ = currentDir.Close()
			currentDir = nextDir
			currentPath = nextPath

			// If we are operating on a .., make sure we haven't escaped. We
			// only have to check for ".." here because walking down into a
			// regular component component cannot cause you to escape. This
			// mirrors the logic in RESOLVE_IN_ROOT, except we have to check
			// every ".." rather than only checking after a rename or mount on
			// the system.
			if part == ".." {
				// Make sure the root hasn't moved.
				if err := checkProcSelfFdPath(logicalRootPath, root); err != nil {
					return nil, "", fmt.Errorf("root path moved during lookup: %w", err)
				}
				// Make sure the path is what we expect.
				fullPath := logicalRootPath + nextPath
				if err := checkProcSelfFdPath(fullPath, nextDir); err != nil {
					return nil, "", fmt.Errorf("walking into .. had unexpected result: %w", err)
				}
			}

		case errors.Is(err, os.ErrNotExist):
			// We have hit a final component that doesn't exist, so we have our
			// partial open result. Note that we have to use the OLD remaining
			// path, since the lookup failed.
			return currentDir, oldRemainingPath, nil

		case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
			// (O_PATH|O_NOFOLLOW) and O_DIRECTORY means we cannot tell if we
			// hit a symlink or some other non-directory component from the
			// error, but we have to readlink the target anyway so we can check
			// that way so assume it's a symlink.
			linkDest, err := readlinkatFile(currentDir, part)
			if err != nil {
				if errors.Is(err, unix.EINVAL) {
					// The part was not a symlink, so assume that it's a
					// regular file. It is possible for it to be a directory
					// (if an attacker is swapping a directory and
					// non-directory at this subpath) but erroring out here is
					// better anyway.
					err = fmt.Errorf("path component is invalid: %w", unix.ENOTDIR)
				}
				return nil, "", err
			}

			linksWalked++
			if linksWalked > maxSymlinkLimit {
				return nil, "", &os.PathError{Op: "partialLookupInRoot", Path: logicalRootPath + "/" + unsafePath, Err: unix.ELOOP}
			}

			// Update our logical remaining path.
			remainingPath = linkDest + "/" + remainingPath
			// Absolute symlinks reset any work we've already done.
			if path.IsAbs(linkDest) {
				// Jump to root.
				rootClone, err := dupFile(root)
				if err != nil {
					return nil, "", fmt.Errorf("clone root fd: %w", err)
				}
				_ = currentDir.Close()
				currentDir = rootClone
				currentPath = "/"
			}

		default:
			return nil, "", err
		}
	}
	// All of the components existed!
	return currentDir, "", nil
}
