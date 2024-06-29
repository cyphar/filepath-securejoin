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
	procSelfFdHandle *os.File
	procSelfFdError  error
	procSelfFdOnce   sync.Once

	errUnsafeProcfs = errors.New("unsafe procfs detected")
)

func doGetProcSelfFd() (*os.File, error) {
	// TODO: Use fsopen or open_tree to get a safe handle that cannot be
	// over-mounted and we can absolutely verify.

	procRoot, err := os.OpenFile("/proc", unix.O_PATH|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer procRoot.Close()
	if err := verifyProcRoot(procRoot); err != nil {
		return nil, err
	}

	handle, err := openatFile(procRoot, "self/fd", unix.O_PATH|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnsafeProcfs, err)
	}
	// We can't detect bind-mounts of different parts of procfs on top of
	// /proc (a-la RESOLVE_NO_XDEV), but we can at least be sure that we
	// aren't on the wrong filesystem here.
	if statfs, err := fstatfs(handle); err != nil {
		return nil, err
	} else if statfs.Type != PROC_SUPER_MAGIC {
		return nil, fmt.Errorf("%w: incorrect /proc/self/fd filesystem type 0x%x", errUnsafeProcfs, statfs.Type)
	}
	return handle, nil
}

func getProcSelfFd() (*os.File, error) {
	procSelfFdOnce.Do(func() {
		procSelfFdHandle, procSelfFdError = doGetProcSelfFd()
	})
	return procSelfFdHandle, procSelfFdError
}

func procSelfFdReadlink(f *os.File) (string, error) {
	// NOTE: It is possible for an attacker to bind-mount on top of the
	// /proc/self/fd/... symlink, and there is currently no way for us to
	// detect this. So we just have to assume that hasn't happened...
	procSelfFd, err := getProcSelfFd()
	if err != nil {
		return "", fmt.Errorf("get safe procfs handle: %w", err)
	}
	// readlinkat(</proc/self/fd>, "42")
	return readlinkatFile(procSelfFd, strconv.Itoa(int(f.Fd())))
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
