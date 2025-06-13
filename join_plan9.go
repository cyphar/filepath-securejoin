// Copyright (C) 2014-2015 Docker Inc & Go Authors. All rights reserved.
// Copyright (C) 2017-2025 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import "path/filepath"

// SecureJoin is equivalent to filepath.Join, as plan9 doesn't have symlinks.
func SecureJoin(root, unsafePath string) (string, error) {
	unsafePath = filepath.Join(string(filepath.Separator), unsafePath)
	return filepath.Join(root, unsafePath), nil
}

// SecureJoinVFS is equivalent to filepath.Join, as plan9 doesn't have symlinks.
func SecureJoinVFS(root, unsafePath string, _ VFS) (string, error) {
	return SecureJoin(root, unsafePath)
}
