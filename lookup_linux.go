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
		// If we logically hit the root, just clone the root rather than
		// opening the part and doing all of the other checks.
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

		// Try to open the next component.
		nextDir, err := openatFile(currentDir, part, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		switch {
		case err == nil:
			st, err := nextDir.Stat()
			if err != nil {
				_ = nextDir.Close()
				return nil, "", fmt.Errorf("stat component %q: %w", part, err)
			}

			switch st.Mode() & os.ModeType {
			case os.ModeDir:
				// If we are dealing with a directory, simply walk into it.
				_ = currentDir.Close()
				currentDir = nextDir
				currentPath = nextPath

				// If we are operating on a .., make sure we haven't escaped.
				// We only have to check for ".." here because walking down
				// into a regular component component cannot cause you to
				// escape. This mirrors the logic in RESOLVE_IN_ROOT, except we
				// have to check every ".." rather than only checking after a
				// rename or mount on the system.
				if part == ".." {
					// Make sure the root hasn't moved.
					if err := checkProcSelfFdPath(logicalRootPath, root); err != nil {
						return nil, "", fmt.Errorf("root path moved during lookup: %w", err)
					}
					// Make sure the path is what we expect.
					fullPath := logicalRootPath + nextPath
					if err := checkProcSelfFdPath(fullPath, currentDir); err != nil {
						return nil, "", fmt.Errorf("walking into %q had unexpected result: %w", part, err)
					}
				}

			case os.ModeSymlink:
				// We don't need the handle anymore.
				_ = nextDir.Close()

				// Unfortunately, we cannot readlink through our handle and so
				// we need to do a separate readlinkat (which could race to
				// give us an error if the attacker swapped the symlink with a
				// non-symlink).
				linkDest, err := readlinkatFile(currentDir, part)
				if err != nil {
					if errors.Is(err, unix.EINVAL) {
						// The part was not a symlink, so assume that it's a
						// regular file. It is possible for it to be a
						// directory (if an attacker is swapping a directory
						// and non-directory at this subpath) but erroring out
						// here is better anyway.
						err = fmt.Errorf("%w: path component %q is invalid: %w", errPossibleAttack, part, unix.ENOTDIR)
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
				// For any other file type, we can't walk further and so we've
				// hit the end of the lookup. The handling is very similar to
				// ENOENT from openat(2), except that we return a handle to the
				// component we just walked into (and we drop the component
				// from the symlink stack).
				_ = currentDir.Close()

				// The current component exists, so return it.
				return nextDir, remainingPath, nil
			}

		case errors.Is(err, os.ErrNotExist):
			// We have hit a final component that doesn't exist, so we have our
			// partial open result. Note that we have to use the OLD remaining
			// path, since the lookup failed.
			return currentDir, oldRemainingPath, nil

		default:
			return nil, "", err
		}
	}
	// All of the components existed!
	return currentDir, "", nil
}
