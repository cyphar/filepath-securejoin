// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && go1.21

// Copyright (C) 2024-2025 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gocompat

import (
	"slices"
	"sync"
)

// SlicesDeleteFunc is equivalent to Go 1.21's slices.DeleteFunc.
func SlicesDeleteFunc[S ~[]E, E any](slice S, delFn func(E) bool) S {
	return slices.DeleteFunc(slice, delFn)
}

// SlicesContains is equivalent to Go 1.21's slices.Contains.
func SlicesContains[S ~[]E, E comparable](slice S, val E) bool {
	return slices.Contains(slice, val)
}

// SlicesClone is equivalent to Go 1.21's slices.Clone.
func SlicesClone[S ~[]E, E any](slice S) S {
	return slices.Clone(slice)
}

// SyncOnceValue is equivalent to Go 1.21's sync.OnceValue.
func SyncOnceValue[T any](f func() T) func() T {
	return sync.OnceValue(f)
}
