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
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

type symlinkStackEntry struct {
	// (dir, remainingPath) is what we would've returned if the link didn't
	// exist. This matches what openat2(RESOLVE_IN_ROOT) would return in
	// this case.
	dir           *os.File
	remainingPath string
	// linkUnwalked is the remaining path components from the original
	// Readlink which we have yet to walk. When this slice is empty, we
	// drop the link from the stack.
	linkUnwalked []string
}

func (se symlinkStackEntry) String() string {
	return fmt.Sprintf("<%s>/%s [->%s]", se.dir.Name(), se.remainingPath, strings.Join(se.linkUnwalked, "/"))
}

func (se symlinkStackEntry) Close() {
	_ = se.dir.Close()
}

type symlinkStack struct {
	linkStack []*symlinkStackEntry
}

func (s symlinkStack) IsEmpty() bool {
	return len(s.linkStack) == 0
}

func (s *symlinkStack) Close() {
	for _, link := range s.linkStack {
		link.Close()
	}
	// TODO: Switch to clear once we switch to Go 1.21.
	s.linkStack = nil
}

func (s *symlinkStack) Push(dir *os.File, remainingPath, linkTarget string) error {
	// Split the link target and clean up any "" parts.
	linkTargetParts := slices.DeleteFunc(
		strings.Split(linkTarget, "/"),
		func(part string) bool { return part == "" })

	// Don't add a no-op link to the stack. You can't create a no-op link
	// symlink, but if the symlink is /, partialLookupInRoot has already jumped to the
	// root and so there's nothing more to do.
	if len(linkTargetParts) == 0 {
		return nil
	}

	// Copy the directory so the caller doesn't close our copy.
	dirCopy, err := dupFile(dir)
	if err != nil {
		return err
	}

	// Add to the stack.
	s.linkStack = append(s.linkStack, &symlinkStackEntry{
		dir:           dirCopy,
		remainingPath: remainingPath,
		linkUnwalked:  linkTargetParts,
	})
	return nil
}

var errBrokenSymlinkStack = errors.New("[internal error] broken symlink stack")

func (s *symlinkStack) PopPart(part string) error {
	if s.IsEmpty() {
		// If there is nothing in the symlink stack, then the part was from the
		// real path provided by the user, and this is a no-op.
		return nil
	}
	tailEntry := s.linkStack[len(s.linkStack)-1]

	// Double-check that we are popping the component we expect.
	headPart := tailEntry.linkUnwalked[0]
	if headPart != part {
		return fmt.Errorf("%w: trying to pop component %q but the last stack entry is %s (%q)", errBrokenSymlinkStack, part, tailEntry, headPart)
	}

	// Drop the component, and the entry if that was the last component.
	tailEntry.linkUnwalked = tailEntry.linkUnwalked[1:]
	if len(tailEntry.linkUnwalked) == 0 {
		s.linkStack = s.linkStack[:len(s.linkStack)-1]
		tailEntry.Close()
	}
	return nil
}

func (s *symlinkStack) PopLastSymlink() (*os.File, string, bool) {
	if s.IsEmpty() {
		return nil, "", false
	}
	tailEntry := s.linkStack[len(s.linkStack)-1]
	s.linkStack = s.linkStack[:len(s.linkStack)-1]
	return tailEntry.dir, tailEntry.remainingPath, true
}

const maxUnsafeHallucinateDirectoryTries = 20

var errTooManyFakeDirectories = errors.New("encountered too many non-existent paths")

// partialLookupInRoot tries to lookup as much of the request path as possible
// within the provided root (a-la RESOLVE_IN_ROOT) and opens the final existing
// component of the requested path, returning a file handle to the final
// existing component and a string containing the remaining path components.
//
// If unsafeHallucinateDirectories is true, partialLookupInRoot will try to
// emulate the legacy SecureJoin behaviour of treating non-existent paths as
// though they are directories to try to resolve as much of the path as
// possible. In practice, this means that a path like "a/b/doesnotexist/../c"
// will end up being resolved as "a/b/c" if possible. Note that dangling
// symlinks (a symlink that points to a non-existent path) will still result in
// an error being returned, due to how openat2 handles symlinks.
func partialLookupInRoot(root *os.File, unsafePath string, unsafeHallucinateDirectories bool) (_ *os.File, _ string, Err error) {
	unsafePath = filepath.ToSlash(unsafePath) // noop

	// This is very similar to SecureJoin, except that we operate on the
	// components using file descriptors. We then return the last component we
	// managed open, along with the remaining path components not opened.

	// Try to use openat2 if possible.
	if hasOpenat2() {
		return partialLookupOpenat2(root, unsafePath, unsafeHallucinateDirectories)
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

	// symlinkStack is used to emulate how openat2(RESOLVE_IN_ROOT) treats
	// dangling symlinks. If we hit a non-existent path while resolving a
	// symlink, we need to return the (dir, remainingPath) that we had when we
	// hit the symlink (treating the symlink itself as though it were a
	// ENOENT). The set of (dir, remainingPath) sets is stored within the
	// symlinkStack and we add and remove parts when we hit symlink and
	// non-symlink components respectively. We need a stack because of
	// recursive symlinks (symlinks that contain symlink components in their
	// target).
	//
	// Note that the stack is ONLY used for book-keeping. All of the actual
	// path walking logic is still based on currentPath/remainingPath and
	// currentDir (as in SecureJoin).
	var symlinkStack symlinkStack
	defer symlinkStack.Close()

	var (
		linksWalked               int
		hallucinateDirectoryTries int

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
			if err := symlinkStack.PopPart(part); err != nil {
				return nil, "", fmt.Errorf("walking into root with part %q failed: %w", part, err)
			}
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

			// The part was real, so drop it from the symlink stack.
			if err := symlinkStack.PopPart(part); err != nil {
				return nil, "", fmt.Errorf("walking into directory %q failed: %w", part, err)
			}

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
				var fullPath string
				if logicalRootPath == "/" {
					fullPath = nextPath
				} else {
					fullPath = logicalRootPath + nextPath
				}
				if err := checkProcSelfFdPath(fullPath, nextDir); err != nil {
					return nil, "", fmt.Errorf("walking into .. had unexpected result: %w", err)
				}
			}

		case errors.Is(err, os.ErrNotExist):
			// If there are any remaining components in the symlink stack, we
			// are still within a symlink resolution and thus we hit a dangling
			// symlink. So pretend as though the last symlink we saw was ENOENT
			// (to match openat2).
			if oldDir, remainingPath, ok := symlinkStack.PopLastSymlink(); ok {
				_ = currentDir.Close()
				return oldDir, remainingPath, nil
			}
			// If we were asked to "hallucinate" non-existent paths as though
			// they are directories, take the remainingPath and clean it so
			// that any ".." components that would lead us back to real paths
			// can get resolved.
			if oldRemainingPath != "" && unsafeHallucinateDirectories {
				if newRemainingPath := path.Clean(oldRemainingPath); newRemainingPath != oldRemainingPath {
					hallucinateDirectoryTries++
					if hallucinateDirectoryTries > maxUnsafeHallucinateDirectoryTries {
						return nil, "", fmt.Errorf("%w: trying to reconcile non-existent subpath %q", errTooManyFakeDirectories, oldRemainingPath)
					}
					// Continue the lookup using the new remaining path.
					remainingPath = newRemainingPath
					continue
				}
			}
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

			// Remove the symlink component from the existing stack and add the
			// new symlink entry to the stack.
			if err := symlinkStack.PopPart(part); err != nil {
				return nil, "", fmt.Errorf("walking into symlink %q failed: pop old component: %w", part, err)
			}
			if err := symlinkStack.Push(currentDir, oldRemainingPath, linkDest); err != nil {
				return nil, "", fmt.Errorf("walking into symlink %q failed: push symlink: %w", part, err)
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
