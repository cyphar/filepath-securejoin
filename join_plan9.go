// Copyright (C) 2014-2015 Docker Inc & Go Authors. All rights reserved.
// Copyright (C) 2017-2025 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import "path/filepath"

// SecureJoin is equivalent to filepath.Join, as plan9 doesn't have symlinks.
func SecureJoin(root, unsafePath string) (string, error) {
	// The root path must not contain ".." components, otherwise when we join
	// the subpath we will end up with a weird path. We could work around this
	// in other ways but users shouldn't be giving us non-lexical root paths in
	// the first place.
	if hasDotDot(root) {
		return "", errUnsafeRoot
	}

	unsafePath = filepath.Join(string(filepath.Separator), unsafePath)
	return filepath.Join(root, unsafePath), nil
}

// SecureJoinVFS is equivalent to filepath.Join, as plan9 doesn't have symlinks.
func SecureJoinVFS(root, unsafePath string, _ VFS) (string, error) {
	return SecureJoin(root, unsafePath)
}
