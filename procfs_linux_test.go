//go:build linux

// Copyright (C) 2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"errors"
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func setupProcOvermount(t *testing.T) {
	requireRoot(t)

	// Lock our thread because we need to create a custom mount namespace. Each
	// test run is run in its own goroutine (this is not _explicitly_
	// guaranteed by Go but t.FailNow() uses Goexit, which means it has to be
	// true in practice) so locking the test to this thread means the other
	// tests will run on different goroutines.
	//
	// There is no UnlockOSThread() here, to ensure that the Go runtime will
	// kill this thread once this goroutine returns (ensuring no other
	// goroutines run in this context).
	runtime.LockOSThread()

	// New mount namespace (we are multi-threaded with a shared fs so we need
	// CLONE_FS to split us from the other threads in the Go process).
	err := unix.Unshare(unix.CLONE_FS | unix.CLONE_NEWNS)
	require.Nil(t, err, "new mount namespace")

	// Private /.
	err = unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, "")
	require.Nil(t, err)

	// Figure out what /proc/thread-self is for this system.
	procRoot, err := unsafeHostProcRoot()
	require.Nil(t, err, "get real host /proc during setup")
	defer procRoot.Close()

	procThreadSelf, closer, err := procThreadSelf(procRoot, ".")
	require.Nil(t, err, "get real host /proc/thread-self during setup")
	procThreadSelfPath := procThreadSelf.Name()
	_ = procThreadSelf.Close()
	closer() // LockOSThread stacks, so we can call this safely.

	// Create some overmounts on /proc.
	for _, mount := range []struct {
		source, targetSubPath, fsType string
		flags                         uintptr
	}{
		// A tmpfs on top of /proc/thread-self/fdinfo to check whether
		// verifyProcRoot() works on old kernels.
		{"tmpfs", "fdinfo", "tmpfs", 0},
		// A bind-mount of noop-write real procfs file on top of
		// /proc/thread-self/attr/current so we can test whether
		// verifyProcRoot() works for the file case.
		//
		// We don't use procThreadSelf for files in filepath-securejoin, but
		// this is to test the runc-equivalent behaviour for when this logic is
		// moved to libpathrs.
		{"/proc/self/sched", "attr/current", "", unix.MS_BIND},
		// TODO: Add a test for bind-mounting on top of magic-links. We can't
		//       detect this at the moment (and maybe in the fd case this will
		//       be blocked by the kernel...) but it'd be nice to have the
		//       problem written down.
		// TODO: Add a test for mounting on top of /proc/self or
		//       /proc/thread-self. This should be detected with openat2.
	} {
		target := path.Join(procThreadSelfPath, mount.targetSubPath)
		err := unix.Mount(mount.source, target, mount.fsType, mount.flags, "")
		require.Nilf(t, err, "mount(%s, [%s/]%s, %s, 0x%x)", mount.source, procThreadSelfPath, mount.targetSubPath, mount.fsType, mount.flags)
	}
}

type procRootFunc func() (*os.File, error)

func testProcThreadSelf(t *testing.T, procRoot *os.File, subpath string, expectErr bool) {
	handle, closer, err := procThreadSelf(procRoot, subpath)
	if expectErr {
		if err == nil || !errors.Is(err, errUnsafeProcfs) {
			t.Errorf("should have detected /proc/thread-self/%s overmount: %v", subpath, err)
		}
	} else {
		require.Nil(t, err)
		_ = handle.Close()
		closer() // LockOSThread stacks, so we can call this safely.
	}
}

func testProcOvermount(t *testing.T, procRootFn procRootFunc, expectOvermounts bool) {
	setupProcOvermount(t)

	procRoot, err := procRootFn()
	require.Nil(t, err)
	defer procRoot.Close()

	// We expect to always detect tmpfs overmounts if we have a /proc with
	// overmounts.
	detectFdinfo := expectOvermounts
	// We only expect to detect procfs bind-mounts if there are /proc
	// overmounts and we have openat2.
	detectAttrCurrent := expectOvermounts && hasOpenat2()

	testProcThreadSelf(t, procRoot, "fdinfo", detectFdinfo)
	testProcThreadSelf(t, procRoot, "attr/current", detectAttrCurrent)
}

func TestProcOvermount_unsafeHostProcRoot(t *testing.T) {
	withWithoutOpenat2(t, func(t *testing.T) {
		// If we use the host /proc directly, we should see overmounts.
		testProcOvermount(t, unsafeHostProcRoot, true)
	})
}

func TestProcOvermount_newPrivateProcMount(t *testing.T) {
	if !hasNewMountApi() {
		t.Skip("test requires fsopen/open_tree support")
	}
	withWithoutOpenat2(t, func(t *testing.T) {
		// If we create our own procfs, the overmounts shouldn't appear.
		testProcOvermount(t, newPrivateProcMount, false)
	})
}

func TestProcOvermount_clonePrivateProcMount(t *testing.T) {
	if !hasNewMountApi() {
		t.Skip("test requires fsopen/open_tree support")
	}
	withWithoutOpenat2(t, func(t *testing.T) {
		// If we use open_tree(2), we don't use AT_RECURSIVE when running in
		// this test (because the overmounts are not locked mounts) and so we
		// don't expect to see overmounts.
		// TODO: Explicitly test AT_RECURSIVE
		testProcOvermount(t, clonePrivateProcMount, false)
	})
}
