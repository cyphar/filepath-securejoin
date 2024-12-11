//go:build linux

// Copyright (C) 2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoCompatErrorWrap(t *testing.T) {
	baseErr := errors.New("base error")
	extraErr := errors.New("extra error")

	err := wrapBaseError(baseErr, extraErr)

	require.Error(t, err)
	assert.ErrorIs(t, err, baseErr, "wrapped error should contain base error")
	assert.ErrorIs(t, err, extraErr, "wrapped error should contain extra error")
}
