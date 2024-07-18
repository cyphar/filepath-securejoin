// Copyright (C) 2017-2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"testing"
)

func TestSymlink(t *testing.T) {
	withWithoutOpenat2(t, true, testSymlink)
}
