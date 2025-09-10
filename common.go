// Copyright (C) 2014-2015 Docker Inc & Go Authors. All rights reserved.
// Copyright (C) 2017-2025 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// IsNotExist tells you if err is an error that implies that either the path
// accessed does not exist (or path components don't exist). This is
// effectively a more broad version of [os.IsNotExist].
func IsNotExist(err error) bool {
	// Check that it's not actually an ENOTDIR, which in some cases is a more
	// convoluted case of ENOENT (usually involving weird paths).
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ENOENT)
}

// errUnsafeRoot is returned if the user provides SecureJoinVFS with a path
// that contains ".." components.
var errUnsafeRoot = errors.New("root path provided to SecureJoin contains '..' components")

// hasDotDot checks if the path contains ".." components in a platform-agnostic
// way.
func hasDotDot(path string) bool {
	// If we are on Windows, strip any volume letters. It turns out that
	// C:..\foo may (or may not) be a valid pathname and we need to handle that
	// leading "..".
	path = stripVolume(path)
	// Look for "/../" in the path, but we need to handle leading and trailing
	// ".."s by adding separators. Doing this with filepath.Separator is ugly
	// so just convert to Unix-style "/" first.
	path = filepath.ToSlash(path)
	return strings.Contains("/"+path+"/", "/../")
}

// stripVolume just gets rid of the Windows volume included in a path. Based on
// some godbolt tests, the Go compiler is smart enough to make this a no-op on
// Linux.
func stripVolume(path string) string {
	return path[len(filepath.VolumeName(path)):]
}
