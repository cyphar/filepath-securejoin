// SPDX-License-Identifier: MPL-2.0

//go:build linux

// Copyright (C) 2024-2025 Aleksa Sarai <cyphar@cyphar.com>
// Copyright (C) 2024-2025 SUSE LLC
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package securejoin

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/cyphar/filepath-securejoin/internal/assert"
	"github.com/cyphar/filepath-securejoin/internal/fd"
	"github.com/cyphar/filepath-securejoin/internal/gocompat"
	"github.com/cyphar/filepath-securejoin/internal/kernelversion"
)

func fstat(f fd.Fd) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &stat); err != nil {
		return stat, &os.PathError{Op: "fstat", Path: f.Name(), Err: err}
	}
	return stat, nil
}

func fstatfs(f fd.Fd) (unix.Statfs_t, error) {
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
func verifyProcHandle(procHandle fd.Fd) error {
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
func verifyProcRoot(procRoot fd.Fd) error {
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

var hasNewMountAPI = gocompat.SyncOnceValue(func() bool {
	// All of the pieces of the new mount API we use (fsopen, fsconfig,
	// fsmount, open_tree) were added together in Linux 5.2[1,2], so we can
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

	// RHEL 8 has a backport of fsopen(2) that appears to have some very
	// difficult to debug performance pathology. As such, it seems prudent to
	// simply reject pre-5.2 kernels.
	isNotBackport, _ := kernelversion.GreaterEqualThan(kernelversion.KernelVersion{5, 2})
	return isNotBackport
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

func fsmount(ctx fd.Fd, flags, mountAttrs int) (*os.File, error) {
	// Make sure we always set O_CLOEXEC.
	flags |= unix.FSMOUNT_CLOEXEC
	fd, err := unix.Fsmount(int(ctx.Fd()), flags, mountAttrs)
	if err != nil {
		return nil, os.NewSyscallError("fsmount "+ctx.Name(), err)
	}
	return os.NewFile(uintptr(fd), "fsmount:"+ctx.Name()), nil
}

type procfsFeatures struct {
	// hasSubsetPid was added in Linux 5.8, along with hidepid=ptraceable (and
	// string-based hidepid= values). Before this patchset, it was not really
	// safe to try to modify procfs superblock flags because the superblock was
	// shared -- so if this feature is not available, **you should not set any
	// superblock flags**.
	//
	// 6814ef2d992a ("proc: add option to mount only a pids subset")
	// fa10fed30f25 ("proc: allow to mount many instances of proc in one pid namespace")
	// 24a71ce5c47f ("proc: instantiate only pids that we can ptrace on 'hidepid=4' mount option")
	// 1c6c4d112e81 ("proc: use human-readable values for hidepid")
	// 9ff7258575d5 ("Merge branch 'proc-linus' of git://git.kernel.org/pub/scm/linux/kernel/git/ebiederm/user-namespace")
	hasSubsetPid bool
}

var getProcfsFeatures = gocompat.SyncOnceValue(func() procfsFeatures {
	if !hasNewMountAPI() {
		return procfsFeatures{}
	}
	procfsCtx, err := fsopen("proc", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return procfsFeatures{}
	}
	defer procfsCtx.Close() //nolint:errcheck // close failures aren't critical here

	return procfsFeatures{
		hasSubsetPid: unix.FsconfigSetString(int(procfsCtx.Fd()), "subset", "pid") == nil,
	}
})

func newPrivateProcMount(subset bool) (_ *ProcfsHandle, Err error) {
	procfsCtx, err := fsopen("proc", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	defer procfsCtx.Close() //nolint:errcheck // close failures aren't critical here

	if subset && getProcfsFeatures().hasSubsetPid {
		// Try to configure hidepid=ptraceable,subset=pid if possible, but
		// ignore errors.
		_ = unix.FsconfigSetString(int(procfsCtx.Fd()), "hidepid", "ptraceable")
		_ = unix.FsconfigSetString(int(procfsCtx.Fd()), "subset", "pid")
	}

	// Get an actual handle.
	if err := unix.FsconfigCreate(int(procfsCtx.Fd())); err != nil {
		return nil, os.NewSyscallError("fsconfig create procfs", err)
	}
	// TODO: Output any information from the fscontext log to debug logs.
	procRoot, err := fsmount(procfsCtx, unix.FSMOUNT_CLOEXEC, unix.MS_NODEV|unix.MS_NOEXEC|unix.MS_NOSUID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if Err != nil {
			_ = procRoot.Close()
		}
	}()
	return newProcfsHandle(procRoot)
}

func openTree(dir fd.Fd, path string, flags uint) (*os.File, error) {
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

func clonePrivateProcMount() (_ *ProcfsHandle, Err error) {
	// Try to make a clone without using AT_RECURSIVE if we can. If this works,
	// we can be sure there are no over-mounts and so if the root is valid then
	// we're golden. Otherwise, we have to deal with over-mounts.
	procRoot, err := openTree(nil, "/proc", unix.OPEN_TREE_CLONE)
	if err != nil || hookForcePrivateProcRootOpenTreeAtRecursive(procRoot) {
		procRoot, err = openTree(nil, "/proc", unix.OPEN_TREE_CLONE|unix.AT_RECURSIVE)
	}
	if err != nil {
		return nil, fmt.Errorf("creating a detached procfs clone: %w", err)
	}
	defer func() {
		if Err != nil {
			_ = procRoot.Close()
		}
	}()
	return newProcfsHandle(procRoot)
}

func privateProcRoot(subset bool) (*ProcfsHandle, error) {
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

func unsafeHostProcRoot() (_ *ProcfsHandle, Err error) {
	procRoot, err := os.OpenFile("/proc", unix.O_PATH|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if Err != nil {
			_ = procRoot.Close()
		}
	}()
	return newProcfsHandle(procRoot)
}

// ProcfsHandle is a wrapper around an *os.File handle to "/proc", which can be
// used to do further procfs-related operations in a safe way.
type ProcfsHandle struct {
	inner fd.Fd
	// TODO: When getting a subset=pid handle, cache it and make Close() a
	//       no-op so that code can work with both setups without leaking
	//       non-subset=pid handles.
}

func newProcfsHandle(procRoot fd.Fd) (*ProcfsHandle, error) {
	if err := verifyProcRoot(procRoot); err != nil {
		// This is only used in methods that
		_ = procRoot.Close()
		return nil, err
	}
	return &ProcfsHandle{inner: procRoot}, nil
}

// Close closes the underlying file for the ProcfsHandle.
func (proc *ProcfsHandle) Close() error { return proc.inner.Close() }

// OpenProcRoot tries to open a "safer" handle to "/proc" (i.e., one with the
// "subset=pid" mount option applied, available from Linux 5.8). Unless you
// plan to do many operations with [ProcRoot], users should prefer to use this
// over [OpenUnsafeProcRoot] which is far more dangerous to keep open.
//
// If a safe handle cannot be opened, OpenProcRoot will fall back to opening a
// regular "/proc" handle.
//
// Note that using [ProcRoot] will still work with handles returned by this
// function. If a [ProcRoot] subpath cannot be operated on with a safe "/proc"
// handle, then [OpenUnsafeProcRoot] will be called internally and a temporary
// unsafe handle will be used.
func OpenProcRoot() (*ProcfsHandle, error) { return getProcRoot(true) }

// OpenUnsafeProcRoot opens a handle to "/proc" without any overmounts or
// masked paths. You must be extremely careful to make sure this handle is
// never leaked to a container and that you program cannot be tricked into
// writing to arbitrary paths within it.
//
// This is not necessary if you just wish to use [ProcRoot], as handles
// returned by [OpenProcRoot] will fall back to using a *temporary* unsafe
// handle in that case. You should only really use this if you need to do many
// operations on [ProcRoot] and the performance overhead of making many procfs
// handles is an issue, and you should make sure to close the handle as soon as
// possible to avoid known-fd-number attacks.
func OpenUnsafeProcRoot() (*ProcfsHandle, error) { return getProcRoot(false) }

func getProcRoot(subset bool) (*ProcfsHandle, error) {
	proc, err := privateProcRoot(subset)
	if err != nil {
		// Fall back to using a /proc handle if making a private mount failed.
		// If we have openat2, at least we can avoid some kinds of over-mount
		// attacks, but without openat2 there's not much we can do.
		proc, err = unsafeHostProcRoot()
	}
	return proc, err
}

var hasProcThreadSelf = gocompat.SyncOnceValue(func() bool {
	return unix.Access("/proc/thread-self/", unix.F_OK) == nil
})

var errUnsafeProcfs = errors.New("unsafe procfs detected")

// lookup is a very minimal wrapper around [procfsLookupInRoot] which is
// intended to be called from the external API.
func (proc *ProcfsHandle) lookup(subpath string) (*os.File, error) {
	handle, err := procfsLookupInRoot(proc.inner, subpath)
	if err != nil {
		return nil, err
	}
	return handle, nil
}

// procfsBase is an enum indicating the prefix of a subpath in operations
// involving [ProcfsHandle]s.
type procfsBase string

const (
	// ProcRoot refers to the root of the procfs (i.e., "/proc/<subpath>").
	ProcRoot procfsBase = "/proc"
	// ProcSelf refers to the current process' subdirectory (i.e.,
	// "/proc/self/<subpath>").
	ProcSelf procfsBase = "/proc/self"
	// ProcThreadSelf refers to the current thread's subdirectory (i.e.,
	// "/proc/thread-self/<subpath>"). In multi-threaded programs (i.e., all Go
	// programs) where one thread has a different CLONE_FS, it is possible for
	// "/proc/self" to point the wrong thread and so "/proc/thread-self" may be
	// necessary. Note that on pre-3.17 kernels, "/proc/thread-self" doesn't
	// exist and so a fallback will be used in that case.
	ProcThreadSelf procfsBase = "/proc/thread-self"
	// TODO: Switch to an interface setup so we can have a more type-safe
	// version of ProcPid and remove the need to worry about invalid string
	// values.
)

// prefix returns a prefix that can be used with the given [ProcfsHandle].
func (base procfsBase) prefix(proc *ProcfsHandle) (string, error) {
	switch base {
	case ProcRoot:
		return ".", nil
	case ProcSelf:
		return "self", nil
	case ProcThreadSelf:
		threadSelf := "thread-self"
		if !hasProcThreadSelf() || hookForceProcSelfTask() {
			// Pre-3.17 kernels don't have /proc/thread-self, so do it
			// manually.
			threadSelf = "self/task/" + strconv.Itoa(unix.Gettid())
			if err := faccessatFile(proc.inner, threadSelf, unix.F_OK, unix.AT_SYMLINK_NOFOLLOW); err != nil || hookForceProcSelf() {
				// In this case, we running in a pid namespace that doesn't
				// match the /proc mount we have. This can happen inside runc.
				//
				// Unfortunately, there is no nice way to get the correct TID
				// to use here because of the age of the kernel, so we have to
				// just use /proc/self and hope that it works.
				threadSelf = "self"
			}
		}
		return threadSelf, nil
	}
	return "", fmt.Errorf("invalid procfs base %q", base)
}

// ProcThreadSelfCloser is a callback that needs to be called when you are done
// operating on an [os.File] fetched using [ProcThreadSelf].
//
// [os.File]: https://pkg.go.dev/os#File
type ProcThreadSelfCloser func()

// Open is the core lookup operation for [ProcfsHandle]. It returns a handle to
// "/proc/<base>/<subpath>". If the returned [ProcThreadSelfCloser] is non-nil,
// you should call it after you are done interacting with the returned handle.
//
// In general you should use prefer to use the other helpers, as they remove
// the need to interact with [procfsBase] and do not return a nil
// [ProcThreadSelfCloser] for [procfsBase] values other than [ProcThreadSelf]
// where it is necessary.
func (proc *ProcfsHandle) open(base procfsBase, subpath string) (_ *os.File, closer ProcThreadSelfCloser, Err error) {
	prefix, err := base.prefix(proc)
	if err != nil {
		return nil, nil, err
	}
	subpath = prefix + "/" + subpath

	switch base {
	case ProcRoot:
		file, err := proc.lookup(subpath)
		if errors.Is(err, os.ErrNotExist) {
			// The ProcfsHandle handle in use might be a subset=pid one, which
			// will result in spurious errors. In this case, just open a
			// temporary unmasked procfs handle for this operation.
			proc, err2 := OpenUnsafeProcRoot() // !subset=pid
			if err2 != nil {
				return nil, nil, err
			}
			defer proc.Close() //nolint:errcheck // close failures aren't critical here

			file, err = proc.lookup(subpath)
		}
		return file, nil, err

	case ProcSelf:
		file, err := proc.lookup(subpath)
		return file, nil, err

	case ProcThreadSelf:
		// We need to lock our thread until the caller is done with the handle
		// because between getting the handle and using it we could get
		// interrupted by the Go runtime and hit the case where the underlying
		// thread is swapped out and the original thread is killed, resulting
		// in pull-your-hair-out-hard-to-debug issues in the caller.
		runtime.LockOSThread()
		defer func() {
			if Err != nil {
				runtime.UnlockOSThread()
				closer = nil
			}
		}()

		file, err := proc.lookup(subpath)
		return file, runtime.UnlockOSThread, err
	}
	// should never be reached
	return nil, nil, fmt.Errorf("[internal error] invalid procfs base %q", base)
}

// OpenThreadSelf returns a handle to "/proc/thread-self/<subpath>" (or an
// equivalent handle on older kernels where "/proc/thread-self" doesn't exist).
// Once finished with the handle, you must call the returned closer function
// (runtime.UnlockOSThread). You must not pass the returned *os.File to other
// Go threads or use the handle after calling the closer.
func (proc *ProcfsHandle) OpenThreadSelf(subpath string) (_ *os.File, _ ProcThreadSelfCloser, Err error) {
	return proc.open(ProcThreadSelf, subpath)
}

// OpenSelf returns a handle to /proc/self/<subpath>.
//
// Note that in Go programs with non-homogenous threads, this may result in
// spurious errors. If you are monkeying around with APIs that are
// thread-specific, you probably want to use [ProcThreadSelf] instead which
// will guarantee that the handle refers to the same thread as the caller is
// executing on.
func (proc *ProcfsHandle) OpenSelf(subpath string) (*os.File, error) {
	file, closer, err := proc.open(ProcSelf, subpath)
	assert.Assert(closer == nil, "closer for ProcSelf must be nil")
	return file, err
}

// OpenRoot returns a handle to /proc/<subpath>.
//
// You should only use this when you need to operate on global procfs files
// (such as sysctls in /proc/sys). Unlike [OpenThreadSelf], [OpenSelf], and
// [ProcPid], the procfs handle used internally for this operation will never
// use subset=pids, which makes it a more juicy target for CVE-2024-21626-style
// attacks.
func (proc *ProcfsHandle) OpenRoot(subpath string) (*os.File, error) {
	file, closer, err := proc.open(ProcRoot, subpath)
	assert.Assert(closer == nil, "closer for ProcRoot must be nil")
	return file, err
}

// OpenPid returns a handle to /proc/$pid/<subpath> (pid can be a pid or tid).
// This is mainly intended for usage when operating on other processes.
//
// You should not use this for the current thread, as special handling is
// needed for /proc/thread-self (or /proc/self/task/<tid>) when dealing with
// goroutine scheduling -- use [OpenThreadSelf] instead.
//
// To refer to the current thread-group, you should use prefer [OpenSelf] to
// passing os.Getpid as the pid argument.
//
// If you want to operate on the top-level /proc filesystem, you should use
// [OpenRoot] instead.
func (proc *ProcfsHandle) OpenPid(pid int, subpath string) (*os.File, error) {
	return proc.OpenRoot(strconv.Itoa(pid) + "/" + subpath)
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

var hasStatxMountID = gocompat.SyncOnceValue(func() bool {
	var stx unix.Statx_t
	err := unix.Statx(-int(unix.EBADF), "/", 0, wantStatxMntMask, &stx)
	return err == nil && stx.Mask&wantStatxMntMask != 0
})

func getMountID(dir fd.Fd, path string) (uint64, error) {
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
		err = gocompat.WrapBaseError(fmt.Errorf("could not get mount id: %w", err), errUnsafeProcfs)
	}
	if err != nil {
		return 0, &os.PathError{Op: "statx(STATX_MNT_ID_...)", Path: fullPath, Err: err}
	}
	runtime.KeepAlive(dir)
	return stx.Mnt_id, nil
}

func checkSubpathOvermount(procRoot fd.Fd, dir fd.Fd, path string) error {
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

// readlink performs a readlink operation on "/proc/<base>/<subpath>" in a way
// that should be free from race attacks. This is most commonly used to get the
// real path of a file by looking at "/proc/self/fd/$n", with the same safety
// protections as [Open] (as well as some additional checks against
// overmounts).
func (proc *ProcfsHandle) readlink(base procfsBase, subpath string) (string, error) {
	link, closer, err := proc.open(base, subpath)
	if closer != nil {
		defer closer()
	}
	if err != nil {
		return "", fmt.Errorf("get safe %s/%s handle: %w", base, subpath, err)
	}
	defer link.Close() //nolint:errcheck // close failures aren't critical here

	// Try to detect if there is a mount on top of the magic-link. This should
	// be safe in general (a mount on top of the path afterwards would not
	// affect the handle itself) and will definitely be safe if we are using
	// privateProcRoot() (at least since Linux 5.12[1], when anonymous mount
	// namespaces were completely isolated from external mounts including mount
	// propagation events).
	//
	// [1]: Linux commit ee2e3f50629f ("mount: fix mounting of detached mounts
	// onto targets that reside on shared mounts").
	if err := checkSubpathOvermount(proc.inner, link, ""); err != nil {
		return "", fmt.Errorf("check safety of %s/%s magiclink: %w", base, subpath, err)
	}

	// readlinkat implies AT_EMPTY_PATH since Linux 2.6.39. See Linux commit
	// 65cfc6722361 ("readlinkat(), fchownat() and fstatat() with empty
	// relative pathnames").
	return readlinkatFile(link, "")
}

func rawProcSelfFdReadlink(fd int) (string, error) {
	procRoot, err := OpenProcRoot() // subset=pid
	if err != nil {
		return "", err
	}
	defer procRoot.Close() //nolint:errcheck // close failures aren't critical here

	return procRoot.readlink(ProcThreadSelf, "fd/"+strconv.Itoa(fd))
}

func procSelfFdReadlink(fd fd.Fd) (string, error) {
	linkname, err := rawProcSelfFdReadlink(int(fd.Fd()))
	runtime.KeepAlive(fd)
	return linkname, err
}

// ProcSelfFdReadlink gets the real path of the given file by looking at
// readlink(/proc/thread-self/fd/$n).
//
// This is just a wrapper around [ProcfsHandle.Readlink].
func ProcSelfFdReadlink(f *os.File) (string, error) {
	return procSelfFdReadlink(f)
}

var (
	errPossibleBreakout = errors.New("possible breakout detected")
	errInvalidDirectory = errors.New("wandered into deleted directory")
	errDeletedInode     = errors.New("cannot verify path of deleted inode")
)

func isDeadInode(file fd.Fd) error {
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

func checkProcSelfFdPath(path string, file fd.Fd) error {
	if err := isDeadInode(file); err != nil {
		return err
	}
	actualPath, err := procSelfFdReadlink(file)
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

func hookDummy() bool                { return false }
func hookDummyFile(_ io.Closer) bool { return false }
