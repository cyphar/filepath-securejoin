// Copyright (C) 2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func symlink(t *testing.T, oldname, newname string) {
	err := os.Symlink(oldname, newname)
	require.NoError(t, err)
}

func mkdirAll(t *testing.T, path string, mode os.FileMode) { //nolint:unparam // wrapper func
	err := os.MkdirAll(path, mode)
	require.NoError(t, err)
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	err := os.WriteFile(path, data, mode)
	require.NoError(t, err)
}
