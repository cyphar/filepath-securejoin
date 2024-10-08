//go:build linux

// Copyright (C) 2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func doMount(t *testing.T, source, target, fsType string, flags uintptr) {
	var sourcePath string
	if source != "" {
		// In order to be able to bind-mount a symlink source we need to
		// bind-mount using an O_PATH|O_NOFOLLOW of the source.
		file, err := os.OpenFile(source, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		require.NoError(t, err)
		defer runtime.KeepAlive(file)
		defer file.Close()
		sourcePath = fmt.Sprintf("/proc/self/fd/%d", file.Fd())
	}

	var targetPath string
	if target != "" {
		// In order to be able to mount on top of symlinks we need to
		// bind-mount through an O_PATH|O_NOFOLLOW of the target.
		file, err := os.OpenFile(target, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		require.NoError(t, err)
		defer runtime.KeepAlive(file)
		defer file.Close()
		targetPath = fmt.Sprintf("/proc/self/fd/%d", file.Fd())
	}

	err := unix.Mount(sourcePath, targetPath, fsType, flags, "")
	if errors.Is(err, unix.ENOENT) {
		// Future kernels will block these kinds of mounts by marking all of
		// these dentries with dont_mount(), which returns -ENOENT from mount.
		// See <https://lore.kernel.org/all/20240806-work-procfs-v1-0-fb04e1d09f0c@kernel.org/>,
		// which should make it into Linux 6.12. So ignore those errors.
		t.Skipf("current kernel does not allow /proc overmounts -- all proc operations are implicitly safe")
	}
	require.NoErrorf(t, err, "mount(%s<%s>, %s<%s>, %s, 0x%x)", sourcePath, source, targetPath, target, fsType, flags)
}

func setupMountNamespace(t *testing.T) {
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
	require.NoError(t, err, "new mount namespace")

	// Private /.
	err = unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, "")
	require.NoError(t, err)
}

func testProcThreadSelf(t *testing.T, procRoot *os.File, subpath string, expectErr bool) {
	handle, closer, err := procThreadSelf(procRoot, subpath)
	if expectErr {
		assert.ErrorIsf(t, err, errUnsafeProcfs, "should have detected /proc/thread-self/%s overmount", subpath)
	} else if assert.NoErrorf(t, err, "/proc/thread-self/%s open should succeed", subpath) {
		_ = handle.Close()
		closer() // LockOSThread stacks, so we can call this safely.
	}
}

type procRootFunc func() (*os.File, error)

func testProcOvermountSubdir(t *testing.T, procRootFn procRootFunc, expectOvermounts bool) {
	testForceProcThreadSelf(t, func(t *testing.T) {
		setupMountNamespace(t)

		// Create some overmounts on /proc/{thread-self/,self/}.
		for _, procThreadSelfPath := range []string{
			fmt.Sprintf("/proc/self/task/%d", unix.Gettid()),
			"/proc/self",
		} {
			for _, mount := range []struct {
				source, targetSubPath, fsType string
				flags                         uintptr
			}{
				// A tmpfs on top of /proc/thread-self/fdinfo to check whether
				// verifyProcRoot() works on old kernels.
				{"", "fdinfo", "tmpfs", 0},
				// A bind-mount of noop-write real procfs file on top of
				// /proc/thread-self/attr/current so we can test whether
				// verifyProcRoot() works for the file case.
				//
				// We don't use procThreadSelf for files in filepath-securejoin, but
				// this is to test the runc-equivalent behaviour for when this logic is
				// moved to libpathrs.
				{"/proc/self/sched", "attr/current", "", unix.MS_BIND},
				// Bind-mounts on top of symlinks should be detected by
				// checkSymlinkOvermount.
				{"/proc/1/fd/0", "exe", "", unix.MS_BIND},
				{"/proc/1/exe", "fd/0", "", unix.MS_BIND},
				// TODO: Add a test for mounting on top of /proc/self or
				//       /proc/thread-self. This should be detected with openat2.
			} {
				target := path.Join(procThreadSelfPath, mount.targetSubPath)
				doMount(t, mount.source, target, mount.fsType, mount.flags)
			}
		}

		procRoot, err := procRootFn()
		require.NoError(t, err)
		defer procRoot.Close()

		// We expect to always detect tmpfs overmounts if we have a /proc with
		// overmounts.
		detectFdinfo := expectOvermounts
		testProcThreadSelf(t, procRoot, "fdinfo", detectFdinfo)
		// We only expect to detect procfs bind-mounts if there are /proc
		// overmounts and we have openat2.
		detectAttrCurrent := expectOvermounts && hasOpenat2()
		testProcThreadSelf(t, procRoot, "attr/current", detectAttrCurrent)

		// For magic-links we expect to detect overmounts if there are any.
		symlinkOvermountErr := errUnsafeProcfs
		if !expectOvermounts {
			symlinkOvermountErr = nil
		}

		procSelf, closer, err := procThreadSelf(procRoot, ".")
		require.NoError(t, err)
		defer procSelf.Close()
		defer closer()

		// Open these paths directly to emulate a non-openat2 handle that
		// didn't detect a bind-mount to check that checkSymlinkOvermount works
		// properly for AT_EMPTY_PATH checks as well.
		procCwd, err := openatFile(procSelf, "cwd", unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		require.NoError(t, err)
		defer procCwd.Close()
		procExe, err := openatFile(procSelf, "exe", unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		require.NoError(t, err)
		defer procExe.Close()

		// no overmount
		err = checkSymlinkOvermount(procRoot, procCwd, "")
		assert.NoError(t, err, "checking /proc/self/cwd with no overmount should succeed")
		err = checkSymlinkOvermount(procRoot, procSelf, "cwd")
		assert.NoError(t, err, "checking /proc/self/cwd with no overmount should succeed")
		// basic overmount
		err = checkSymlinkOvermount(procRoot, procExe, "")
		assert.ErrorIs(t, err, symlinkOvermountErr, "unexpected /proc/self/exe overmount result")
		err = checkSymlinkOvermount(procRoot, procSelf, "exe")
		assert.ErrorIs(t, err, symlinkOvermountErr, "unexpected /proc/self/exe overmount result")

		// fd no overmount
		_, err = doRawProcSelfFdReadlink(procRoot, 1)
		assert.NoError(t, err, "checking /proc/self/fd/1 with no overmount should succeed")
		// fd overmount
		link, err := doRawProcSelfFdReadlink(procRoot, 0)
		assert.ErrorIs(t, err, symlinkOvermountErr, "unexpected /proc/self/fd/0 overmount result: got link %q", link)
	})
}

func TestProcOvermountSubdir_unsafeHostProcRoot(t *testing.T) {
	withWithoutOpenat2(t, true, func(t *testing.T) {
		// If we use the host /proc directly, we should see overmounts.
		testProcOvermountSubdir(t, unsafeHostProcRoot, true)
	})
}

func TestProcOvermountSubdir_newPrivateProcMount(t *testing.T) {
	if !hasNewMountApi() {
		t.Skip("test requires fsopen/open_tree support")
	}
	withWithoutOpenat2(t, true, func(t *testing.T) {
		// If we create our own procfs, the overmounts shouldn't appear.
		testProcOvermountSubdir(t, newPrivateProcMount, false)
	})
}

func TestProcOvermountSubdir_clonePrivateProcMount(t *testing.T) {
	if !hasNewMountApi() {
		t.Skip("test requires fsopen/open_tree support")
	}
	withWithoutOpenat2(t, true, func(t *testing.T) {
		// If we use open_tree(2), we don't use AT_RECURSIVE when running in
		// this test (because the overmounts are not locked mounts) and so we
		// don't expect to see overmounts.
		testProcOvermountSubdir(t, clonePrivateProcMount, false)
	})
}

func TestProcOvermountSubdir_doGetProcRoot(t *testing.T) {
	withWithoutOpenat2(t, true, func(t *testing.T) {
		// We expect to not get overmounts if we have the new mount API.
		// FIXME: It's possible to hit overmounts if there are locked mounts
		// and we hit the AT_RECURSIVE case...
		testProcOvermountSubdir(t, doGetProcRoot, !hasNewMountApi())
	})
}

func TestProcOvermountSubdir_doGetProcRoot_Mocked(t *testing.T) {
	if !hasNewMountApi() {
		t.Skip("test requires fsopen/open_tree support")
	}
	withWithoutOpenat2(t, true, func(t *testing.T) {
		testForceGetProcRoot(t, func(t *testing.T, expectOvermounts bool) {
			testProcOvermountSubdir(t, doGetProcRoot, expectOvermounts)
		})
	})
}

func canFsOpen() bool {
	f, err := fsopen("tmpfs", 0)
	if f != nil {
		_ = f.Close()
	}
	return err == nil
}

func testProcOvermount(t *testing.T, procRootFn procRootFunc, privateProcMount bool) {
	testForceProcThreadSelf(t, func(t *testing.T) {
		for _, mount := range []struct {
			source, fsType string
			flags          uintptr
		}{
			// Try a non-procfs filesystem overmount.
			{"", "tmpfs", 0},
			// Try a procfs subdir overmount.
			{"/proc/tty", "bind", unix.MS_BIND},
		} {
			mount := mount // copy iterator
			t.Run("procmount="+mount.fsType, func(t *testing.T) {
				setupMountNamespace(t)
				doMount(t, mount.source, "/proc", mount.fsType, mount.flags)

				procRoot, err := procRootFn()
				if procRoot != nil {
					defer procRoot.Close()
				}
				if privateProcMount {
					assert.NoError(t, err, "get proc handle should succeed")
					assert.NoError(t, verifyProcRoot(procRoot), "verify private proc mount should succeed")
				} else {
					if !assert.ErrorIs(t, err, errUnsafeProcfs, "get proc handle should fail") {
						t.Logf("procRootFn() = %v, %v", procRoot, err)
					}
				}
			})
		}
	})
}

func TestProcOvermount_unsafeHostProcRoot(t *testing.T) {
	testProcOvermount(t, unsafeHostProcRoot, false)
}

func TestProcOvermount_clonePrivateProcMount(t *testing.T) {
	if !hasNewMountApi() {
		t.Skip("test requires open_tree support")
	}
	testProcOvermount(t, clonePrivateProcMount, false)
}

func TestProcOvermount_newPrivateProcMount(t *testing.T) {
	if !hasNewMountApi() || !canFsOpen() {
		t.Skip("test requires fsopen support")
	}
	testProcOvermount(t, newPrivateProcMount, true)
}

func TestProcOvermount_doGetProcRoot(t *testing.T) {
	privateProcMount := canFsOpen() && !testingForcePrivateProcRootOpenTree(nil)
	testProcOvermount(t, doGetProcRoot, privateProcMount)
}

func TestProcOvermount_doGetProcRoot_Mocked(t *testing.T) {
	if !hasNewMountApi() {
		t.Skip("test requires fsopen/open_tree support")
	}
	testForceGetProcRoot(t, func(t *testing.T, expectOvermounts bool) {
		privateProcMount := canFsOpen() && !testingForcePrivateProcRootOpenTree(nil)
		testProcOvermount(t, doGetProcRoot, privateProcMount)
	})
}

func TestProcSelfFdPath(t *testing.T) {
	testForceProcThreadSelf(t, func(t *testing.T) {
		root := t.TempDir()

		filePath := path.Join(root, "file")
		err := unix.Mknod(filePath, unix.S_IFREG|0o644, 0)
		require.NoError(t, err)

		symPath := path.Join(root, "sym")
		err = unix.Symlink(filePath, symPath)
		require.NoError(t, err)

		// Open through the symlink.
		handle, err := os.Open(symPath)
		defer handle.Close()

		// The check should fail if we expect the symlink path.
		err = checkProcSelfFdPath(symPath, handle)
		assert.ErrorIs(t, err, errPossibleBreakout, "checkProcSelfFdPath should fail for wrong path")

		// The check should fail if we expect the symlink path.
		err = checkProcSelfFdPath(filePath, handle)
		assert.NoError(t, err)
	})
}

func TestProcSelfFdPath_DeadFile(t *testing.T) {
	testForceProcThreadSelf(t, func(t *testing.T) {
		root := t.TempDir()

		fullPath := path.Join(root, "file")
		handle, err := os.Create(fullPath)
		require.NoError(t, err)
		defer handle.Close()

		// The path still exists.
		err = checkProcSelfFdPath(fullPath, handle)
		assert.NoError(t, err, "checkProcSelfFdPath should succeed with regular file")

		// Delete the path.
		err = os.Remove(fullPath)
		require.NoError(t, err)

		// The check should fail now.
		err = checkProcSelfFdPath(fullPath, handle)
		assert.ErrorIs(t, err, errDeletedInode, "checkProcSelfFdPath should fail after deletion")

		// The check should fail even if the expected path ends with " (deleted)".
		err = checkProcSelfFdPath(fullPath+" (deleted)", handle)
		assert.ErrorIs(t, err, errDeletedInode, "checkProcSelfFdPath should fail after deletion even with (deleted) suffix")
	})
}

func TestProcSelfFdPath_DeadDir(t *testing.T) {
	testForceProcThreadSelf(t, func(t *testing.T) {
		root := t.TempDir()

		fullPath := path.Join(root, "dir")
		err := os.Mkdir(fullPath, 0o755)
		require.NoError(t, err)

		handle, err := os.OpenFile(fullPath, unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		require.NoError(t, err)
		defer handle.Close()

		// The path still exists.
		err = checkProcSelfFdPath(fullPath, handle)
		assert.NoError(t, err, "checkProcSelfFdPath should succeed with regular directory")

		// Delete the path.
		err = os.Remove(fullPath)
		require.NoError(t, err)

		// The check should fail now.
		err = checkProcSelfFdPath(fullPath, handle)
		assert.ErrorIs(t, err, errInvalidDirectory, "checkProcSelfFdPath should fail after deletion")

		// The check should fail even if the expected path ends with " (deleted)".
		err = checkProcSelfFdPath(fullPath+" (deleted)", handle)
		assert.ErrorIs(t, err, errInvalidDirectory, "checkProcSelfFdPath should fail after deletion even with (deleted) suffix")
	})
}

func testVerifyProcRoot(t *testing.T, procRoot string, expectedErr error, errString string) {
	fakeProcRoot, err := os.OpenFile(procRoot, unix.O_PATH|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	defer fakeProcRoot.Close()

	err = verifyProcRoot(fakeProcRoot)
	assert.ErrorIsf(t, err, expectedErr, "verifyProcRoot(%s)", procRoot)
	if expectedErr != nil {
		assert.ErrorContainsf(t, err, errString, "verifyProcRoot(%s)", procRoot)
	}
}

func TestVerifyProcRoot_Regular(t *testing.T) {
	testForceProcThreadSelf(t, func(t *testing.T) {
		testVerifyProcRoot(t, "/proc", nil, "")
	})
}

func TestVerifyProcRoot_ProcNonRoot(t *testing.T) {
	testForceProcThreadSelf(t, func(t *testing.T) {
		testVerifyProcRoot(t, "/proc/self", errUnsafeProcfs, "incorrect procfs root inode number")
		testVerifyProcRoot(t, "/proc/mounts", errUnsafeProcfs, "incorrect procfs root inode number")
		testVerifyProcRoot(t, "/proc/stat", errUnsafeProcfs, "incorrect procfs root inode number")
	})
}

func TestVerifyProcRoot_NotProc(t *testing.T) {
	testForceProcThreadSelf(t, func(t *testing.T) {
		testVerifyProcRoot(t, "/", errUnsafeProcfs, "incorrect procfs root filesystem type")
		testVerifyProcRoot(t, ".", errUnsafeProcfs, "incorrect procfs root filesystem type")
		testVerifyProcRoot(t, t.TempDir(), errUnsafeProcfs, "incorrect procfs root filesystem type")
	})
}

func TestProcfsDummyHooks(t *testing.T) {
	assert.False(t, hookDummy(), "hookDummy should always return false")
	assert.False(t, hookDummyFile(nil), "hookDummyFile should always return false")
}
