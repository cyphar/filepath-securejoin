//go:build linux && go1.21

// Copyright (C) 2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"slices"
	"sync"
)

func slices_DeleteFunc[S ~[]E, E any](slice S, delFn func(E) bool) S { //nolint:revive // name is meant to mirror stdlib
	return slices.DeleteFunc(slice, delFn)
}

func slices_Contains[S ~[]E, E comparable](slice S, val E) bool { //nolint:revive // name is meant to mirror stdlib
	return slices.Contains(slice, val)
}

func slices_Clone[S ~[]E, E any](slice S) S { //nolint:revive // name is meant to mirror stdlib
	return slices.Clone(slice)
}

func sync_OnceValue[T any](f func() T) func() T { //nolint:revive // name is meant to mirror stdlib
	return sync.OnceValue(f)
}
