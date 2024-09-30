//go:build linux

// Copyright (C) 2024 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func requireRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test requires root")
	}
}

func withWithoutOpenat2(t *testing.T, doAuto bool, testFn func(t *testing.T)) {
	if doAuto {
		t.Run("openat2=auto", testFn)
	}
	for _, useOpenat2 := range []bool{true, false} {
		useOpenat2 := useOpenat2 // copy iterator
		t.Run(fmt.Sprintf("openat2=%v", useOpenat2), func(t *testing.T) {
			if useOpenat2 && !hasOpenat2() {
				t.Skip("no openat2 support")
			}
			origHasOpenat2 := hasOpenat2
			hasOpenat2 = func() bool { return useOpenat2 }
			defer func() { hasOpenat2 = origHasOpenat2 }()

			testFn(t)
		})
	}
}

func testForceGetProcRoot(t *testing.T, testFn func(t *testing.T, expectOvermounts bool)) {
	for _, test := range []struct {
		name             string
		forceGetProcRoot forceGetProcRootLevel
		expectOvermounts bool
	}{
		{`procfd="fsopen()"`, forceGetProcRootDefault, false},
		{`procfd="open_tree_clone"`, forceGetProcRootOpenTree, false},
		{`procfd="open_tree_clone(AT_RECURSIVE)"`, forceGetProcRootOpenTreeAtRecursive, true},
		{`procfd="open()"`, forceGetProcRootUnsafe, true},
	} {
		test := test // copy iterator
		t.Run(test.name, func(t *testing.T) {
			testingForceGetProcRoot = &test.forceGetProcRoot
			defer func() { testingForceGetProcRoot = nil }()

			testFn(t, test.expectOvermounts)
		})
	}
}

func testForceProcThreadSelf(t *testing.T, testFn func(t *testing.T)) {
	for _, test := range []struct {
		name                string
		forceProcThreadSelf forceProcThreadSelfLevel
	}{
		{`thread-self="thread-self"`, forceProcThreadSelfDefault},
		{`thread-self="self/task"`, forceProcSelfTask},
		{`thread-self="self"`, forceProcSelf},
	} {
		test := test // copy iterator
		t.Run(test.name, func(t *testing.T) {
			testingForceProcThreadSelf = &test.forceProcThreadSelf
			defer func() { testingForceProcThreadSelf = nil }()

			testFn(t)
		})
	}
}

func hasRenameExchange() bool {
	err := unix.Renameat2(unix.AT_FDCWD, ".", unix.AT_FDCWD, ".", unix.RENAME_EXCHANGE)
	return !errors.Is(err, unix.ENOSYS)
}

func doRenameExchangeLoop(pauseCh chan struct{}, exitCh <-chan struct{}, dir *os.File, pathA, pathB string) {
	for {
		select {
		case <-exitCh:
			return
		case <-pauseCh:
			// Wait for caller to unpause us.
			select {
			case pauseCh <- struct{}{}:
			case <-exitCh:
				return
			}
		default:
			// Do the swap twice so that we only pause when we are in a
			// "correct" state.
			for i := 0; i < 2; i++ {
				err := unix.Renameat2(int(dir.Fd()), pathA, int(dir.Fd()), pathB, unix.RENAME_EXCHANGE)
				if err != nil && int(dir.Fd()) != -1 && !errors.Is(err, unix.EBADF) {
					// Should never happen, and if it does we will potentially
					// enter a bad filesystem state if we get paused.
					panic(fmt.Sprintf("renameat2([%d]%q, %q, ..., %q, RENAME_EXCHANGE) = %v", int(dir.Fd()), dir.Name(), pathA, pathB, err))
				}
			}
		}
		// Make sure GC doesn't close the directory handle.
		runtime.KeepAlive(dir)
	}
}

// Format:
//
//	dir <name> <?uid:gid:mode>
//	file <name> <?content> <?uid:gid:mode>
//	symlink <name> <target>
//	char <name> <major> <minor> <?uid:gid:mode>
//	block <name> <major> <minor> <?uid:gid:mode>
//	fifo <name> <?uid:gid:mode>
//	sock <name> <?uid:gid:mode>
func createInTree(t *testing.T, root, spec string) {
	f := strings.Fields(spec)
	if len(f) < 2 {
		t.Fatalf("invalid spec %q", spec)
	}
	inoType, subPath, f := f[0], f[1], f[2:]
	fullPath := filepath.Join(root, subPath)

	var setOwnerMode *string
	switch inoType {
	case "dir":
		if len(f) >= 1 {
			setOwnerMode = &f[0]
		}
		err := os.MkdirAll(fullPath, 0o755)
		require.NoError(t, err)
	case "file":
		var contents []byte
		if len(f) >= 1 {
			contents = []byte(f[0])
		}
		if len(f) >= 2 {
			setOwnerMode = &f[1]
		}
		err := os.WriteFile(fullPath, contents, 0o644)
		require.NoError(t, err)
	case "symlink":
		if len(f) < 1 {
			t.Fatalf("invalid spec %q", spec)
		}
		target := f[0]
		err := os.Symlink(target, fullPath)
		require.NoError(t, err)
	case "char", "block":
		if len(f) < 2 {
			t.Fatalf("invalid spec %q", spec)
		}
		if len(f) >= 3 {
			setOwnerMode = &f[2]
		}

		major, err := strconv.Atoi(f[0])
		require.NoErrorf(t, err, "mknod %s: parse major", subPath)
		minor, err := strconv.Atoi(f[1])
		require.NoErrorf(t, err, "mknod %s: parse minor", subPath)
		dev := unix.Mkdev(uint32(major), uint32(minor))

		var mode uint32 = 0o644
		switch inoType {
		case "char":
			mode |= unix.S_IFCHR
		case "block":
			mode |= unix.S_IFBLK
		}
		err = unix.Mknod(fullPath, mode, int(dev))
		require.NoErrorf(t, err, "mknod (%s %d:%d) %s", inoType, major, minor, fullPath)
	case "fifo", "sock":
		if len(f) >= 1 {
			setOwnerMode = &f[0]
		}
		var mode uint32 = 0o644
		switch inoType {
		case "fifo":
			mode |= unix.S_IFIFO
		case "sock":
			mode |= unix.S_IFSOCK
		}
		err := unix.Mknod(fullPath, mode, 0)
		require.NoErrorf(t, err, "mk%s %s", inoType, fullPath)
	}
	if setOwnerMode != nil {
		// <?uid>:<?gid>:<?mode>
		fields := strings.Split(*setOwnerMode, ":")
		require.Lenf(t, fields, 3, "set owner-mode format uid:gid:mode")
		uidStr, gidStr, modeStr := fields[0], fields[1], fields[2]

		if uidStr != "" && gidStr != "" {
			uid, err := strconv.Atoi(uidStr)
			require.NoErrorf(t, err, "chown %s: parse uid", fullPath)
			gid, err := strconv.Atoi(gidStr)
			require.NoErrorf(t, err, "chown %s: parse gid", fullPath)
			err = unix.Chown(fullPath, uid, gid)
			require.NoErrorf(t, err, "chown %s", fullPath)
		}

		if modeStr != "" {
			mode, err := strconv.ParseUint(modeStr, 8, 32)
			require.NoErrorf(t, err, "chmod %s: parse mode", fullPath)
			err = unix.Chmod(fullPath, uint32(mode))
			require.NoErrorf(t, err, "chmod %s", fullPath)
		}
	}
}

func createTree(t *testing.T, specs ...string) string {
	root := t.TempDir()

	// Put the root in a subdir.
	treeRoot := filepath.Join(root, "tree")
	os.MkdirAll(treeRoot, 0o755)

	for _, spec := range specs {
		createInTree(t, treeRoot, spec)
	}
	return treeRoot
}
