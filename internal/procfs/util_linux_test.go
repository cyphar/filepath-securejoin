// SPDX-License-Identifier: MPL-2.0

//go:build linux

// Copyright (C) 2024-2025 Aleksa Sarai <cyphar@cyphar.com>
// Copyright (C) 2024-2025 SUSE LLC
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package procfs

import (
	"fmt"
	"os"
	"testing"

	"github.com/cyphar/filepath-securejoin/internal/linux"
)

func requireRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test requires root")
	}
}

func withWithoutOpenat2(t *testing.T, doAuto bool, testFn func(t *testing.T)) { //nolint:unparam // doAuto comes from the impl in the main package
	if doAuto {
		t.Run("openat2=auto", testFn)
	}
	for _, useOpenat2 := range []bool{true, false} {
		useOpenat2 := useOpenat2 // copy iterator
		t.Run(fmt.Sprintf("openat2=%v", useOpenat2), func(t *testing.T) {
			if useOpenat2 && !linux.HasOpenat2() {
				t.Skip("no openat2 support")
			}
			origHasOpenat2 := linux.HasOpenat2
			linux.HasOpenat2 = func() bool { return useOpenat2 }
			defer func() { linux.HasOpenat2 = origHasOpenat2 }()

			testFn(t)
		})
	}
}

func testForceGetProcRoot(t *testing.T, testFn func(t *testing.T, expectOvermounts bool)) {
	for _, test := range []struct {
		name             string
		forceGetProcRoot forceGetProcRootLevel
		expectOvermounts bool
	}{
		{`procfd="fsopen()"`, forceGetProcRootDefault, false},
		{`procfd="open_tree_clone"`, forceGetProcRootOpenTree, false},
		{`procfd="open_tree_clone(AT_RECURSIVE)"`, forceGetProcRootOpenTreeAtRecursive, true},
		{`procfd="open()"`, forceGetProcRootUnsafe, true},
	} {
		test := test // copy iterator
		t.Run(test.name, func(t *testing.T) {
			testingForceGetProcRoot = &test.forceGetProcRoot
			defer func() { testingForceGetProcRoot = nil }()

			testFn(t, test.expectOvermounts)
		})
	}
}

func testForceProcThreadSelf(t *testing.T, testFn func(t *testing.T)) {
	for _, test := range []struct {
		name                string
		forceProcThreadSelf forceProcThreadSelfLevel
	}{
		{`thread-self="thread-self"`, forceProcThreadSelfDefault},
		{`thread-self="self/task"`, forceProcSelfTask},
		{`thread-self="self"`, forceProcSelf},
	} {
		test := test // copy iterator
		t.Run(test.name, func(t *testing.T) {
			testingForceProcThreadSelf = &test.forceProcThreadSelf
			defer func() { testingForceProcThreadSelf = nil }()

			testFn(t)
		})
	}
}
