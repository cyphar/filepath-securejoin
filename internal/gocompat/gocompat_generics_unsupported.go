// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !go1.21

// Copyright (C) 2021, 2022 The Go Authors. All rights reserved.
// Copyright (C) 2024-2025 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gocompat

import (
	"sync"
)

// These are very minimal implementations of functions that appear in Go 1.21's
// stdlib, included so that we can build on older Go versions. Most are
// borrowed directly from the stdlib, and a few are modified to be "obviously
// correct" without needing to copy too many other helpers.

// clearSlice is equivalent to Go 1.21's builtin clear.
// Copied from the Go 1.24 stdlib implementation.
func clearSlice[S ~[]E, E any](slice S) {
	var zero E
	for i := range slice {
		slice[i] = zero
	}
}

// slicesIndexFunc is equivalent to Go 1.21's slices.IndexFunc.
// Copied from the Go 1.24 stdlib implementation.
func slicesIndexFunc[S ~[]E, E any](s S, f func(E) bool) int {
	for i := range s {
		if f(s[i]) {
			return i
		}
	}
	return -1
}

// SlicesDeleteFunc is equivalent to Go 1.21's slices.DeleteFunc.
// Copied from the Go 1.24 stdlib implementation.
func SlicesDeleteFunc[S ~[]E, E any](s S, del func(E) bool) S {
	i := slicesIndexFunc(s, del)
	if i == -1 {
		return s
	}
	// Don't start copying elements until we find one to delete.
	for j := i + 1; j < len(s); j++ {
		if v := s[j]; !del(v) {
			s[i] = v
			i++
		}
	}
	clearSlice(s[i:]) // zero/nil out the obsolete elements, for GC
	return s[:i]
}

// SlicesContains is equivalent to Go 1.21's slices.Contains.
// Similar to the stdlib slices.Contains, except that we don't have
// slices.Index so we need to use slices.IndexFunc for this non-Func helper.
func SlicesContains[S ~[]E, E comparable](s S, v E) bool {
	return slicesIndexFunc(s, func(e E) bool { return e == v }) >= 0
}

// SlicesClone is equivalent to Go 1.21's slices.Clone.
// Copied from the Go 1.24 stdlib implementation.
func SlicesClone[S ~[]E, E any](s S) S {
	// Preserve nil in case it matters.
	if s == nil {
		return nil
	}
	return append(S([]E{}), s...)
}

// SyncOnceValue is equivalent to Go 1.21's sync.OnceValue.
// Copied from the Go 1.25 stdlib implementation.
func SyncOnceValue[T any](f func() T) func() T {
	// Use a struct so that there's a single heap allocation.
	d := struct {
		f      func() T
		once   sync.Once
		valid  bool
		p      any
		result T
	}{
		f: f,
	}
	return func() T {
		d.once.Do(func() {
			defer func() {
				d.f = nil
				d.p = recover()
				if !d.valid {
					panic(d.p)
				}
			}()
			d.result = d.f()
			d.valid = true
		})
		if !d.valid {
			panic(d.p)
		}
		return d.result
	}
}

// SyncOnceValues is equivalent to Go 1.21's sync.OnceValues.
// Copied from the Go 1.25 stdlib implementation.
func SyncOnceValues[T1, T2 any](f func() (T1, T2)) func() (T1, T2) {
	// Use a struct so that there's a single heap allocation.
	d := struct {
		f     func() (T1, T2)
		once  sync.Once
		valid bool
		p     any
		r1    T1
		r2    T2
	}{
		f: f,
	}
	return func() (T1, T2) {
		d.once.Do(func() {
			defer func() {
				d.f = nil
				d.p = recover()
				if !d.valid {
					panic(d.p)
				}
			}()
			d.r1, d.r2 = d.f()
			d.valid = true
		})
		if !d.valid {
			panic(d.p)
		}
		return d.r1, d.r2
	}
}
