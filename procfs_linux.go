//go:build linux

// Copyright (C) 2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"

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
	PROC_SUPER_MAGIC = 0x9fa0
	PROC_ROOT_INO    = 1
)

func verifyProcRoot(procRoot *os.File) error {
	if statfs, err := fstatfs(procRoot); err != nil {
		return err
	} else if statfs.Type != PROC_SUPER_MAGIC {
		return fmt.Errorf("%w: incorrect procfs root filesystem type 0x%x", errUnsafeProcfs, statfs.Type)
	}
	if stat, err := fstat(procRoot); err != nil {
		return err
	} else if stat.Ino != PROC_ROOT_INO {
		return fmt.Errorf("%w: incorrect procfs root inode number %d", errUnsafeProcfs, stat.Ino)
	}
	return nil
}

var (
	procRootHandle *os.File
	procRootError  error
	procRootOnce   sync.Once

	errUnsafeProcfs = errors.New("unsafe procfs detected")
)

func doGetProcRoot() (_ *os.File, Err error) {
	// TODO: Use fsopen or open_tree to get a safe handle that cannot be
	// over-mounted and we can absolutely verify.

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

func getProcRoot() (*os.File, error) {
	procRootOnce.Do(func() {
		procRootHandle, procRootError = doGetProcRoot()
	})
	return procRootHandle, procRootError
}

var (
	haveProcThreadSelf     bool
	haveProcThreadSelfOnce sync.Once
)

type procThreadSelfCloser func()

// procThreadSelf returns a handle to /proc/thread-self/<subpath> (or an
// equivalent handle on older kernels where /proc/thread-self doesn't exist).
// Once finished with the handle, you must call the returned closer function
// (runtime.UnlockOSThread). You must not pass the returned *os.File to other
// Go threads or use the handle after calling the closer.
//
// This is similar to ProcThreadSelf from runc, but with extra hardening
// applied and using *os.File.
func procThreadSelf(subpath string) (_ *os.File, _ procThreadSelfCloser, Err error) {
	procRoot, err := getProcRoot()
	if err != nil {
		return nil, nil, err
	}

	haveProcThreadSelfOnce.Do(func() {
		// If the kernel doesn't support thread-self, it doesn't matter which
		// /proc handle we use.
		_, err := fstatatFile(procRoot, "thread-self", unix.AT_SYMLINK_NOFOLLOW)
		haveProcThreadSelf = (err == nil)
	})

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
	if !haveProcThreadSelf {
		/// Pre-3.17 kernels don't have /proc/thread-self, so do it manually.
		threadSelf = "self/task/" + strconv.Itoa(unix.Gettid()) + "/"
		if _, err := fstatatFile(procRoot, threadSelf, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			// In this case, we running in a pid namespace that doesn't match
			// the /proc mount we have. This can happen inside runc.
			//
			// Unfortunately, there is no nice way to get the correct TID to
			// use here because of the age of the kernel, so we have to just
			// use /proc/self and hope that it works.
			threadSelf = "self/"
		}
	}

	// Grab the handle.
	var handle *os.File
	if hasOpenat2() {
		// We prefer being able to use RESOLVE_NO_XDEV if we can, to be
		// absolutely sure we are operating on a clean /proc handle that
		// doesn't have any cheeky overmounts that could trick us (including
		// symlink mounts on top of /proc/thread-self). RESOLVE_BENEATH isn't
		// stricly needed, but just use it since we have it.
		//
		// NOTE: /proc/self is technically a magic-link (the contents of the
		//       symlink are generated dynamically), but it doesn't use
		//       nd_jump_link() so RESOLVE_NO_MAGICLINKS allows it.
		//
		// NOTE: We MUST NOT use RESOLVE_IN_ROOT here, as openat2File uses
		//       procSelfFdReadlink to clean up the returned f.Name() if we use
		//       RESOLVE_IN_ROOT (which would lead to an infinite recursion).
		handle, err = openat2File(procRoot, threadSelf+subpath, &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_MAGICLINKS,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", errUnsafeProcfs, err)
		}
	} else {
		handle, err = openatFile(procRoot, threadSelf+subpath, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", errUnsafeProcfs, err)
		}
		// We can't detect bind-mounts of different parts of procfs on top of
		// /proc (a-la RESOLVE_NO_XDEV), but we can at least be sure that we
		// aren't on the wrong filesystem here.
		if statfs, err := fstatfs(handle); err != nil {
			return nil, nil, err
		} else if statfs.Type != PROC_SUPER_MAGIC {
			return nil, nil, fmt.Errorf("%w: incorrect /proc/self/fd filesystem type 0x%x", errUnsafeProcfs, statfs.Type)
		}
	}
	return handle, runtime.UnlockOSThread, nil
}

func rawProcSelfFdReadlink(fd int) (string, error) {
	procSelfFd, closer, err := procThreadSelf("fd/")
	if err != nil {
		return "", fmt.Errorf("get safe /proc/thread-self/fd handle: %w", err)
	}
	defer closer()
	// NOTE: It is possible for an attacker to bind-mount on top of the
	// /proc/self/fd/... symlink, and there is currently no way for us to
	// detect this. So we just have to assume that hasn't happened...
	return readlinkatFile(procSelfFd, strconv.Itoa(fd))
}

func procSelfFdReadlink(f *os.File) (string, error) {
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

func getUmask() int {
	// umask is a per-thread property, but it is inherited by children, so we
	// need to lock our OS thread to make sure that no other goroutine runs in
	// this thread and no goroutines are spawned from this thread until we
	// revert to the old umask.
	//
	// We could parse /proc/self/status to avoid this get-set problem, but
	// /proc/thread-self requires LockOSThread anyway, so there's no real
	// benefit over just using umask(2).
	runtime.LockOSThread()
	umask := unix.Umask(0)
	unix.Umask(umask)
	runtime.UnlockOSThread()
	return umask
}

func checkProcSelfFdPath(path string, file *os.File) error {
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
