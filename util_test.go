// Copyright (C) 2024-2025 Aleksa Sarai <cyphar@cyphar.com>
// Copyright (C) 2024-2025 SUSE LLC
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
