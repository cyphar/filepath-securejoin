//go:build linux

// Copyright (C) 2024-2025 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

func fstat(f *os.File) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &stat); err != nil {
		return stat, &os.PathError{Op: "fstat", Path: f.Name(), Err: err}
	}
	return stat, nil
}

func fstatfs(f *os.File) (unix.Statfs_t, error) {
	var statfs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &statfs); err != nil {
		return statfs, &os.PathError{Op: "fstatfs", Path: f.Name(), Err: err}
	}
	return statfs, nil
}

// The kernel guarantees that the root inode of a procfs mount has an
// f_type of PROC_SUPER_MAGIC and st_ino of PROC_ROOT_INO.
const (
	procSuperMagic = 0x9fa0 // PROC_SUPER_MAGIC
	procRootIno    = 1      // PROC_ROOT_INO
)

// verifyProcHandle checks that the handle is from a procfs filesystem.
// Contrast this to [verifyProcRoot], which also verifies that the handle is
// the root of a procfs mount.
func verifyProcHandle(procHandle *os.File) error {
	if statfs, err := fstatfs(procHandle); err != nil {
		return err
	} else if statfs.Type != procSuperMagic {
		return fmt.Errorf("%w: incorrect procfs root filesystem type 0x%x", errUnsafeProcfs, statfs.Type)
	}
	return nil
}

// verifyProcRoot verifies that the handle is the root of a procfs filesystem.
// Contrast this to [verifyProcHandle], which only verifies if the handle is
// some file on procfs (regardless of what file it is).
func verifyProcRoot(procRoot *os.File) error {
	if err := verifyProcHandle(procRoot); err != nil {
		return err
	}
	if stat, err := fstat(procRoot); err != nil {
		return err
	} else if stat.Ino != procRootIno {
		return fmt.Errorf("%w: incorrect procfs root inode number %d", errUnsafeProcfs, stat.Ino)
	}
	return nil
}

var hasNewMountAPI = sync_OnceValue(func() bool {
	// All of the pieces of the new mount API we use (fsopen, fsconfig,
	// fsmount, open_tree) were added together in Linux 5.1[1,2], so we can
	// just check for one of the syscalls and the others should also be
	// available.
	//
	// Just try to use open_tree(2) to open a file without OPEN_TREE_CLONE.
	// This is equivalent to openat(2), but tells us if open_tree is
	// available (and thus all of the other basic new mount API syscalls).
	// open_tree(2) is most light-weight syscall to test here.
	//
	// [1]: merge commit 400913252d09
	// [2]: <https://lore.kernel.org/lkml/153754740781.17872.7869536526927736855.stgit@warthog.procyon.org.uk/>
	fd, err := unix.OpenTree(-int(unix.EBADF), "/", unix.OPEN_TREE_CLOEXEC)
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
})

func fsopen(fsName string, flags int) (*os.File, error) {
	// Make sure we always set O_CLOEXEC.
	flags |= unix.FSOPEN_CLOEXEC
	fd, err := unix.Fsopen(fsName, flags)
	if err != nil {
		return nil, os.NewSyscallError("fsopen "+fsName, err)
	}
	return os.NewFile(uintptr(fd), "fscontext:"+fsName), nil
}

func fsmount(ctx *os.File, flags, mountAttrs int) (*os.File, error) {
	// Make sure we always set O_CLOEXEC.
	flags |= unix.FSMOUNT_CLOEXEC
	fd, err := unix.Fsmount(int(ctx.Fd()), flags, mountAttrs)
	if err != nil {
		return nil, os.NewSyscallError("fsmount "+ctx.Name(), err)
	}
	return os.NewFile(uintptr(fd), "fsmount:"+ctx.Name()), nil
}

func newPrivateProcMount(subset bool) (*os.File, error) {
	procfsCtx, err := fsopen("proc", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	defer procfsCtx.Close() //nolint:errcheck // close failures aren't critical here

	if subset {
		// Try to configure hidepid=ptraceable,subset=pid if possible, but
		// ignore errors.
		_ = unix.FsconfigSetString(int(procfsCtx.Fd()), "hidepid", "ptraceable")
		_ = unix.FsconfigSetString(int(procfsCtx.Fd()), "subset", "pid")
	}

	// Get an actual handle.
	if err := unix.FsconfigCreate(int(procfsCtx.Fd())); err != nil {
		return nil, os.NewSyscallError("fsconfig create procfs", err)
	}
	return fsmount(procfsCtx, unix.FSMOUNT_CLOEXEC, unix.MS_NODEV|unix.MS_NOEXEC|unix.MS_NOSUID)
}

func openTree(dir *os.File, path string, flags uint) (*os.File, error) {
	dirFd, fullPath := prepareAt(dir, path)
	// Make sure we always set O_CLOEXEC.
	flags |= unix.OPEN_TREE_CLOEXEC
	fd, err := unix.OpenTree(dirFd, path, flags)
	if err != nil {
		return nil, &os.PathError{Op: "open_tree", Path: fullPath, Err: err}
	}
	runtime.KeepAlive(dir)
	return os.NewFile(uintptr(fd), fullPath), nil
}

func clonePrivateProcMount() (_ *os.File, Err error) {
	// Try to make a clone without using AT_RECURSIVE if we can. If this works,
	// we can be sure there are no over-mounts and so if the root is valid then
	// we're golden. Otherwise, we have to deal with over-mounts.
	procfsHandle, err := openTree(nil, "/proc", unix.OPEN_TREE_CLONE)
	if err != nil || hookForcePrivateProcRootOpenTreeAtRecursive(procfsHandle) {
		procfsHandle, err = openTree(nil, "/proc", unix.OPEN_TREE_CLONE|unix.AT_RECURSIVE)
	}
	if err != nil {
		return nil, fmt.Errorf("creating a detached procfs clone: %w", err)
	}
	defer func() {
		if Err != nil {
			_ = procfsHandle.Close()
		}
	}()
	if err := verifyProcRoot(procfsHandle); err != nil {
		return nil, err
	}
	return procfsHandle, nil
}

func privateProcRoot(subset bool) (*os.File, error) {
	if !hasNewMountAPI() || hookForceGetProcRootUnsafe() {
		return nil, fmt.Errorf("new mount api: %w", unix.ENOTSUP)
	}
	// Try to create a new procfs mount from scratch if we can. This ensures we
	// can get a procfs mount even if /proc is fake (for whatever reason).
	procRoot, err := newPrivateProcMount(subset)
	if err != nil || hookForcePrivateProcRootOpenTree(procRoot) {
		// Try to clone /proc then...
		procRoot, err = clonePrivateProcMount()
	}
	return procRoot, err
}

func unsafeHostProcRoot() (_ *os.File, Err error) {
	procRoot, err := os.OpenFile("/proc", unix.O_PATH|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if Err != nil {
			_ = procRoot.Close()
		}
	}()
	if err := verifyProcRoot(procRoot); err != nil {
		return nil, err
	}
	return procRoot, nil
}

func getProcRootSubset() (*os.File, error)   { return getProcRoot(true) }
func getProcRootUnmasked() (*os.File, error) { return getProcRoot(false) }

func getProcRoot(subset bool) (*os.File, error) {
	procRoot, err := privateProcRoot(subset)
	if err != nil {
		// Fall back to using a /proc handle if making a private mount failed.
		// If we have openat2, at least we can avoid some kinds of over-mount
		// attacks, but without openat2 there's not much we can do.
		procRoot, err = unsafeHostProcRoot()
	}
	return procRoot, err
}

var hasProcThreadSelf = sync_OnceValue(func() bool {
	return unix.Access("/proc/thread-self/", unix.F_OK) == nil
})

var errUnsafeProcfs = errors.New("unsafe procfs detected")

// procOpen is a very minimal wrapper around [procfsLookupInRoot] which is
// intended to be called from the external API.
func procOpen(procRoot *os.File, subpath string) (*os.File, error) {
	// If called from the external API, procRoot will be nil, so just get the
	// global root handle. It's also possible one of our tests calls this with
	// nil by accident, so we should handle the case anyway.
	if procRoot == nil {
		root, err := getProcRootSubset() // default to subset=pids
		if err != nil {
			return nil, err
		}
		procRoot = root
		defer procRoot.Close() //nolint:errcheck // close failures aren't critical here
	}

	handle, err := procfsLookupInRoot(procRoot, subpath)
	if err != nil {
		// TODO: Once we bump the minimum Go version to 1.20, we can use
		// multiple %w verbs for this wrapping. For now we need to use a
		// compatibility shim for older Go versions.
		// err = fmt.Errorf("%w: %w", errUnsafeProcfs, err)
		return nil, wrapBaseError(err, errUnsafeProcfs)
	}
	return handle, nil
}

// ProcThreadSelfCloser is a callback that needs to be called when you are done
// operating on an [os.File] fetched using [ProcThreadSelf].
//
// [os.File]: https://pkg.go.dev/os#File
type ProcThreadSelfCloser func()

func procThreadSelf(procRoot *os.File, subpath string) (_ *os.File, _ ProcThreadSelfCloser, Err error) {
	// If called from the external API, procRoot will be nil, so just get the
	// global root handle. It's also possible one of our tests calls this with
	// nil by accident, so we should handle the case anyway.
	if procRoot == nil {
		root, err := getProcRootSubset() // subset=pids
		if err != nil {
			return nil, nil, err
		}
		procRoot = root
		defer procRoot.Close() //nolint:errcheck // close failures aren't critical here
	}

	// We need to lock our thread until the caller is done with the handle
	// because between getting the handle and using it we could get interrupted
	// by the Go runtime and hit the case where the underlying thread is
	// swapped out and the original thread is killed, resulting in
	// pull-your-hair-out-hard-to-debug issues in the caller.
	runtime.LockOSThread()
	defer func() {
		if Err != nil {
			runtime.UnlockOSThread()
		}
	}()

	// Figure out what prefix we want to use.
	threadSelf := "thread-self/"
	if !hasProcThreadSelf() || hookForceProcSelfTask() {
		/// Pre-3.17 kernels don't have /proc/thread-self, so do it manually.
		threadSelf = "self/task/" + strconv.Itoa(unix.Gettid()) + "/"
		if _, err := fstatatFile(procRoot, threadSelf, unix.AT_SYMLINK_NOFOLLOW); err != nil || hookForceProcSelf() {
			// In this case, we running in a pid namespace that doesn't match
			// the /proc mount we have. This can happen inside runc.
			//
			// Unfortunately, there is no nice way to get the correct TID to
			// use here because of the age of the kernel, so we have to just
			// use /proc/self and hope that it works.
			threadSelf = "self/"
		}
	}

	handle, err := procOpen(procRoot, threadSelf+subpath)
	if err != nil {
		return nil, nil, err
	}
	return handle, runtime.UnlockOSThread, nil
}

// ProcThreadSelf returns a handle to /proc/thread-self/<subpath> (or an
// equivalent handle on older kernels where /proc/thread-self doesn't exist).
// Once finished with the handle, you must call the returned closer function
// (runtime.UnlockOSThread). You must not pass the returned *os.File to other
// Go threads or use the handle after calling the closer.
//
// This is similar to ProcThreadSelf from runc, but with extra hardening
// applied and using *os.File.
func ProcThreadSelf(subpath string) (*os.File, ProcThreadSelfCloser, error) {
	return procThreadSelf(nil, subpath)
}

// ProcPid returns a handle to /proc/$pid/<subpath> (pid can be a pid or tid).
// You should not use this for the current thread, as special handling is
// needed for /proc/thread-self (or /proc/self/task/<tid>) when dealing with
// goroutine scheduling -- use [ProcThreadSelf] instead. This is mainly
// intended for usage when operating on other processes.
//
// You should not try to operate on the top-level /proc handle (such as by
// setting subpath to "../foo"). This will not work at all on non-openat2
// systems, and when using an internal fsopen-based handle, the mount will have
// subset=pids and hidepid=traceable set (which will restrict what PIDs can be
// accessed with this API, as well as removing any non-PID procfs files).
func ProcPid(pid int, subpath string) (*os.File, error) {
	return procOpen(nil, strconv.Itoa(pid)+"/"+subpath)
}

const (
	// STATX_MNT_ID_UNIQUE is provided in golang.org/x/sys@v0.20.0, but in order to
	// avoid bumping the requirement for a single constant we can just define it
	// ourselves.
	_STATX_MNT_ID_UNIQUE = 0x4000 //nolint:revive // unix.* name

	// We don't care which mount ID we get. The kernel will give us the unique
	// one if it is supported. If the kernel doesn't support
	// STATX_MNT_ID_UNIQUE, the bit is ignored and the returned request mask
	// will only contain STATX_MNT_ID (if supported).
	wantStatxMntMask = _STATX_MNT_ID_UNIQUE | unix.STATX_MNT_ID
)

var hasStatxMountID = sync_OnceValue(func() bool {
	var stx unix.Statx_t
	err := unix.Statx(-int(unix.EBADF), "/", 0, wantStatxMntMask, &stx)
	return err == nil && stx.Mask&wantStatxMntMask != 0
})

func getMountID(dir *os.File, path string) (uint64, error) {
	// If we don't have statx(STATX_MNT_ID*) support, we can't do anything.
	if !hasStatxMountID() {
		return 0, nil
	}

	dirFd, fullPath := prepareAt(dir, path)

	var stx unix.Statx_t
	err := unix.Statx(dirFd, path, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, wantStatxMntMask, &stx)
	if stx.Mask&wantStatxMntMask == 0 {
		// It's not a kernel limitation, for some reason we couldn't get a
		// mount ID. Assume it's some kind of attack.
		//
		// TODO: Once we bump the minimum Go version to 1.20, we can use
		// multiple %w verbs for this wrapping. For now we need to use a
		// compatibility shim for older Go versions.
		// err = fmt.Errorf("%w: could not get mount id: %w", errUnsafeProcfs, err)
		err = wrapBaseError(fmt.Errorf("could not get mount id: %w", err), errUnsafeProcfs)
	}
	if err != nil {
		return 0, &os.PathError{Op: "statx(STATX_MNT_ID_...)", Path: fullPath, Err: err}
	}
	runtime.KeepAlive(dir)
	return stx.Mnt_id, nil
}

func checkSubpathOvermount(procRoot *os.File, dir *os.File, path string) error {
	// Get the mntID of our procfs handle.
	expectedMountID, err := getMountID(procRoot, "")
	if err != nil {
		return err
	}
	// Get the mntID of the target magic-link.
	gotMountID, err := getMountID(dir, path)
	if err != nil {
		return err
	}
	// As long as the directory mount is alive, even with wrapping mount IDs,
	// we would expect to see a different mount ID here. (Of course, if we're
	// using unsafeHostProcRoot() then an attaker could change this after we
	// did this check.)
	if expectedMountID != gotMountID {
		return fmt.Errorf("%w: subpath %s/%s has an overmount obscuring the real link (mount ids do not match %d != %d)", errUnsafeProcfs, dir.Name(), path, expectedMountID, gotMountID)
	}
	return nil
}

func doRawProcSelfFdReadlink(procRoot *os.File, fd int) (string, error) {
	fdPath := fmt.Sprintf("fd/%d", fd)
	procFdLink, closer, err := procThreadSelf(procRoot, fdPath)
	if err != nil {
		return "", fmt.Errorf("get safe /proc/thread-self/%s handle: %w", fdPath, err)
	}
	defer procFdLink.Close() //nolint:errcheck // close failures aren't critical here
	defer closer()

	// Try to detect if there is a mount on top of the magic-link. This should
	// be safe in general (a mount on top of the path afterwards would not
	// affect the handle itself) and will definitely be safe if we are using
	// privateProcRoot() (at least since Linux 5.12[1], when anonymous mount
	// namespaces were completely isolated from external mounts including mount
	// propagation events).
	//
	// [1]: Linux commit ee2e3f50629f ("mount: fix mounting of detached mounts
	// onto targets that reside on shared mounts").
	if err := checkSubpathOvermount(procRoot, procFdLink, ""); err != nil {
		return "", fmt.Errorf("check safety of /proc/thread-self/fd/%d magiclink: %w", fd, err)
	}

	// readlinkat implies AT_EMPTY_PATH since Linux 2.6.39. See Linux commit
	// 65cfc6722361 ("readlinkat(), fchownat() and fstatat() with empty
	// relative pathnames").
	return readlinkatFile(procFdLink, "")
}

func rawProcSelfFdReadlink(fd int) (string, error) {
	procRoot, err := getProcRootSubset() // subset=pids
	if err != nil {
		return "", err
	}
	defer procRoot.Close() //nolint:errcheck // close failures aren't critical here
	return doRawProcSelfFdReadlink(procRoot, fd)
}

// ProcSelfFdReadlink gets the real path of the given file by looking at
// readlink(/proc/thread-self/fd/$n), with the same safety protections as
// [ProcThreadSelf] (as well as some additional checks against overmounts).
func ProcSelfFdReadlink(f *os.File) (string, error) {
	return rawProcSelfFdReadlink(int(f.Fd()))
}

var (
	errPossibleBreakout = errors.New("possible breakout detected")
	errInvalidDirectory = errors.New("wandered into deleted directory")
	errDeletedInode     = errors.New("cannot verify path of deleted inode")
)

func isDeadInode(file *os.File) error {
	// If the nlink of a file drops to 0, there is an attacker deleting
	// directories during our walk, which could result in weird /proc values.
	// It's better to error out in this case.
	stat, err := fstat(file)
	if err != nil {
		return fmt.Errorf("check for dead inode: %w", err)
	}
	if stat.Nlink == 0 {
		err := errDeletedInode
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			err = errInvalidDirectory
		}
		return fmt.Errorf("%w %q", err, file.Name())
	}
	return nil
}

func checkProcSelfFdPath(path string, file *os.File) error {
	if err := isDeadInode(file); err != nil {
		return err
	}
	actualPath, err := ProcSelfFdReadlink(file)
	if err != nil {
		return fmt.Errorf("get path of handle: %w", err)
	}
	if actualPath != path {
		return fmt.Errorf("%w: handle path %q doesn't match expected path %q", errPossibleBreakout, actualPath, path)
	}
	return nil
}

// Test hooks used in the procfs tests to verify that the fallback logic works.
// See testing_mocks_linux_test.go and procfs_linux_test.go for more details.
var (
	hookForcePrivateProcRootOpenTree            = hookDummyFile
	hookForcePrivateProcRootOpenTreeAtRecursive = hookDummyFile
	hookForceGetProcRootUnsafe                  = hookDummy

	hookForceProcSelfTask = hookDummy
	hookForceProcSelf     = hookDummy
)

func hookDummy() bool               { return false }
func hookDummyFile(_ *os.File) bool { return false }
