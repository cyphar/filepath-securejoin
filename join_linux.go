//go:build linux

// Copyright (C) 2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func isLexicallyInRoot(root, path string) bool {
	if root != "/" {
		root += "/"
	}
	if path != "/" {
		path += "/"
	}
	return strings.HasPrefix(path, root)
}

// SecureJoin is a wrapper around SecureJoinVFS that just uses the os.* library
// of functions as the VFS. If in doubt, use this function over SecureJoinVFS.
func SecureJoin(root, unsafePath string) (string, error) {
	rootDir, err := os.OpenFile(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer rootDir.Close()

	handle, remainingPath, err := partialLookupInRoot(rootDir, unsafePath, true)
	if err != nil {
		return "", err
	}
	defer handle.Close()

	handlePath, err := procSelfFdReadlink(handle)
	if err != nil {
		return "", fmt.Errorf("verify actual path of %q handle: %w", handle.Name(), err)
	}
	// Make sure the path is inside the root.
	if !isLexicallyInRoot(root, handlePath) {
		return "", fmt.Errorf("%w: handle path %q is outside root %q", errPossibleBreakout, handlePath, root)
	}

	// remainingPath should be cleaned and safe to append, due to how
	// unsafeHallucinateDirectories works. But do an additional cleanup, just
	// to be sure.
	remainingPath = filepath.Join("/", remainingPath)
	return filepath.Join(handlePath, remainingPath), nil
}

// SecureJoinVFS joins the two given path components (similar to Join) except
// that the returned path is guaranteed to be scoped inside the provided root
// path (when evaluated). Any symbolic links in the path are evaluated with the
// given root treated as the root of the filesystem, similar to a chroot. The
// filesystem state is evaluated through the given VFS interface (if nil, the
// standard os.* family of functions are used).
//
// Note that the guarantees provided by this function only apply if the path
// components in the returned string are not modified (in other words are not
// replaced with symlinks on the filesystem) after this function has returned.
// Such a symlink race is necessarily out-of-scope of SecureJoin.
//
// Volume names in unsafePath are always discarded, regardless if they are
// provided via direct input or when evaluating symlinks. Therefore:
//
// "C:\Temp" + "D:\path\to\file.txt" results in "C:\Temp\path\to\file.txt"
func SecureJoinVFS(root, unsafePath string, vfs VFS) (string, error) {
	if vfs == nil || vfs == (osVFS{}) {
		return SecureJoin(root, unsafePath)
	}
	// TODO: Make it possible for partialLookupInRoot to work with VFS.
	return legacySecureJoinVFS(root, unsafePath, vfs)
}
