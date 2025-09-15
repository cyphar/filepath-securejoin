// SPDX-License-Identifier: MPL-2.0

//go:build linux

// Copyright (C) 2024-2025 Aleksa Sarai <cyphar@cyphar.com>
// Copyright (C) 2024-2025 SUSE LLC
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package pathrs

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/cyphar/filepath-securejoin/pathrs-lite/internal/procfs"
)

// OpenatInRoot is equivalent to [OpenInRoot], except that the root is provided
// using an *[os.File] handle, to ensure that the correct root directory is used.
func OpenatInRoot(root *os.File, unsafePath string) (*os.File, error) {
	handle, err := completeLookupInRoot(root, unsafePath)
	if err != nil {
		return nil, &os.PathError{Op: "securejoin.OpenInRoot", Path: unsafePath, Err: err}
	}
	return handle, nil
}

// OpenInRoot safely opens the provided unsafePath within the root.
// Effectively, OpenInRoot(root, unsafePath) is equivalent to
//
//	path, _ := securejoin.SecureJoin(root, unsafePath)
//	handle, err := os.OpenFile(path, unix.O_PATH|unix.O_CLOEXEC)
//
// But is much safer. The above implementation is unsafe because if an attacker
// can modify the filesystem tree between [SecureJoin] and [os.OpenFile], it is
// possible for the returned file to be outside of the root.
//
// Note that the returned handle is an O_PATH handle, meaning that only a very
// limited set of operations will work on the handle. This is done to avoid
// accidentally opening an untrusted file that could cause issues (such as a
// disconnected TTY that could cause a DoS, or some other issue). In order to
// use the returned handle, you can "upgrade" it to a proper handle using
// [Reopen].
func OpenInRoot(root, unsafePath string) (*os.File, error) {
	rootDir, err := os.OpenFile(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer rootDir.Close() //nolint:errcheck // close failures aren't critical here
	return OpenatInRoot(rootDir, unsafePath)
}

// Reopen takes an *[os.File] handle and re-opens it through /proc/self/fd.
// Reopen(file, flags) is effectively equivalent to
//
//	fdPath := fmt.Sprintf("/proc/self/fd/%d", file.Fd())
//	os.OpenFile(fdPath, flags|unix.O_CLOEXEC)
//
// But with some extra hardenings to ensure that we are not tricked by a
// maliciously-configured /proc mount. While this attack scenario is not
// common, in container runtimes it is possible for higher-level runtimes to be
// tricked into configuring an unsafe /proc that can be used to attack file
// operations. See [CVE-2019-19921] for more details.
//
// [CVE-2019-19921]: https://github.com/advisories/GHSA-fh74-hm69-rqjw
func Reopen(handle *os.File, flags int) (*os.File, error) {
	procRoot, err := procfs.OpenProcRoot() // subset=pid
	if err != nil {
		return nil, err
	}
	defer procRoot.Close() //nolint:errcheck // close failures aren't critical here

	// We can't operate on /proc/thread-self/fd/$n directly when doing a
	// re-open, so we need to open /proc/thread-self/fd and then open a single
	// final component.
	procFdDir, closer, err := procRoot.OpenThreadSelf("fd/")
	if err != nil {
		return nil, fmt.Errorf("get safe /proc/thread-self/fd handle: %w", err)
	}
	defer procFdDir.Close() //nolint:errcheck // close failures aren't critical here
	defer closer()

	// Try to detect if there is a mount on top of the magic-link we are about
	// to open. If we are using unsafeHostProcRoot(), this could change after
	// we check it (and there's nothing we can do about that) but for
	// privateProcRoot() this should be guaranteed to be safe (at least since
	// Linux 5.12[1], when anonymous mount namespaces were completely isolated
	// from external mounts including mount propagation events).
	//
	// [1]: Linux commit ee2e3f50629f ("mount: fix mounting of detached mounts
	// onto targets that reside on shared mounts").
	fdStr := strconv.Itoa(int(handle.Fd()))
	if err := procfs.CheckSubpathOvermount(procRoot.Inner, procFdDir, fdStr); err != nil {
		return nil, fmt.Errorf("check safety of /proc/thread-self/fd/%s magiclink: %w", fdStr, err)
	}

	flags |= unix.O_CLOEXEC
	// Rather than just wrapping openatFile, open-code it so we can copy
	// handle.Name().
	reopenFd, err := unix.Openat(int(procFdDir.Fd()), fdStr, flags, 0)
	if err != nil {
		return nil, fmt.Errorf("reopen fd %d: %w", handle.Fd(), err)
	}
	return os.NewFile(uintptr(reopenFd), handle.Name()), nil
}
