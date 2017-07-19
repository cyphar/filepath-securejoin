// Copyright (C) 2014-2015 Docker Inc & Go Authors. All rights reserved.
// Copyright (C) 2017 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package securejoin is an implementation of the hopefully-soon-to-be-included
// SecureJoin helper that is meant to be part of the "path/filepath" package.
// The purpose of this project is to provide a PoC implementation to make the
// SecureJoin proposal (https://github.com/golang/go/issues/20126) more
// tangible.
package securejoin

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ErrSymlinkLoop is returned by SecureJoinVFS when too many symlinks have been
// evaluated in attempting to securely join the two given paths.
var ErrSymlinkLoop = errors.New("SecureJoin: too many links")

// SecureJoin joins the two given path components (similar to Join) except that
// the returned path is guaranteed to be scoped inside the provided root path
// (when evaluated). Any symbolic links in the path are evaluated with the
// given root treated as the root of the filesystem, similar to a chroot.
//
// Note that the guarantees provided by this function only apply if the path
// components in the returned string are not modified (in other words are not
// replaced with symlinks on the filesystem) after this function has returned.
// Such a symlink race is necessarily out-of-scope of SecureJoin.
func SecureJoin(root, unsafePath string) (string, error) {
	var path bytes.Buffer
	n := 0
	for unsafePath != "" {
		if n > 255 {
			return "", ErrSymlinkLoop
		}

		// Next path component, p.
		i := strings.IndexRune(unsafePath, filepath.Separator)
		var p string
		if i == -1 {
			p, unsafePath = unsafePath, ""
		} else {
			p, unsafePath = unsafePath[:i], unsafePath[i+1:]
		}

		// Create a cleaned path, using the lexical semantics of /../a, to
		// create a "scoped" path component which can safely be joined to fullP
		// for evaluation. At this point, path.String() doesn't contain any
		// symlink components.
		cleanP := filepath.Clean(string(filepath.Separator) + path.String() + p)
		if cleanP == string(filepath.Separator) {
			path.Reset()
			continue
		}
		fullP := filepath.Clean(root + cleanP)

		// Figure out whether the path is a symlink.
		fi, err := os.Lstat(fullP)
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		// Treat non-existent path components the same as non-symlinks (we
		// can't do any better here).
		if os.IsNotExist(err) || fi.Mode()&os.ModeSymlink == 0 {
			path.WriteString(p)
			path.WriteRune(filepath.Separator)
			continue
		}

		// Only increment when we actually dereference a link.
		n++

		// It's a symlink, expand it by prepending it to the yet-unparsed path.
		dest, err := os.Readlink(fullP)
		if err != nil {
			return "", err
		}
		// Absolute symlinks reset any work we've already done.
		if filepath.IsAbs(dest) {
			path.Reset()
		}
		unsafePath = dest + string(filepath.Separator) + unsafePath
	}

	// We have to clean path.String() here because it may contain '..'
	// components that are entirely lexical, but would be misleading otherwise.
	// And finally do a final clean to ensure that root is also lexically
	// clean.
	fullP := filepath.Clean(string(filepath.Separator) + path.String())
	return filepath.Clean(root + fullP), nil
}
