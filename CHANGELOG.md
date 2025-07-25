# Changelog #
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased] ##

### Added ###
- Some minimal parts of the safe `procfs` API have now been exposed. At the
  moment these include:

   * `ProcThreadSelf` which allows you to get a safe handle `O_PATH` to a
     subpath in `/proc/thread-self` (you can upgrade it to a proper handle with
     `Reopen` like any other `O_PATH` handle). The returned
     `ProcThreadSelfCloser` needs to be called after you completely finish
     using the handle (this is necessary because Go is multi-threaded and
     `ProcThreadSelf` references `/proc/thread-self` which may disappear if we
     do not `runtime.LockOSThread` -- `ProcThreadSelfCloser` is currently
     equivalent to `runtime.UnlockOSThread`).

     Note that you cannot operate on any `procfs` symlinks (most notably
     magiclinks) using this API. At the moment `filepath-securejoin` does not
     support this feature (but [libpathrs][] does).

   * `ProcSelf` is the `/proc/self` equivalent of `ProcThreadSelf`. Unlike
     `ProcThreadSelf`, it is not necessary to lock the goroutine to the current
     thread (since `/proc/self` refers to the thread-group leader and is not
     intended for per-thread operations) and so no `ProcThreadSelfCloser`
     closure will be returned.

   * `ProcPid` is very similar to `ProcThreadSelf`, except it lets you get
     handles to subpaths of other processes.

     Please note that it is possible for you to be unable to access processes
     in certain configurations (when using `fsopen(2)`, the internal procfs
     mount will have `subset=pids,hidepids=traceable` mount options applied,
     which will hide many other processes and any non-process-related top-level
     files). To operate on the current thread-group, prefer to use `ProcSelf`
     rather than `ProcPid(os.Getpid(), ...)` because the latter will not
     necessarily work properly in situations with complicated PID namespace
     setups.

     Also note that if the target process dies, the handle you received from
     `ProcPid` may start returning errors or blank data when you operate on it.

   * `ProcRoot` lets you get access to top-level `/proc` paths, which is
     primarily useful for things like sysctls.

     As this requires access to non-`subset=pids` paths, the internal
     `fsopen("procfs")` handle is not restricted and so you should use this
     method with care. Leaking this file descriptor (even in subtle ways) can
     easily lead to very concerning [CVE-2024-21626][]-style bugs where a
     privileged user could break out of containers.

   * `ProcSelfFdReadlink` lets you get the in-kernel path representation of a
     file descriptor (think `readlink("/proc/self/fd/...")`). This is
     equivalent to doing a `readlinkat(fd, "", ...)` of
     `ProcThreadSelf("fd/%d")`, except that we verify that there aren't any
     tricky overmounts that could fool the process.

     Please be aware that the returned string is simply a snapshot at that
     particular moment, and an attacker could move the file being pointed to.
     In addition, complex namespace configurations could result in non-sensical
     or confusing paths to be returned. The value received from this function
     should only be used as secondary verification of some security property,
     not as proof that a particular handle has a particular path.

  The procfs handle used internally by the API is the same as the rest of
  `filepath-securejoin` (for privileged programs this is usually a private
  in-process `procfs` instance created with `fsopen(2)`).

  As before, this is intended as a stop-gap before users migrate to
  [libpathrs][], which provides a far more extensive safe `procfs` API and is
  generally more robust.

- Previously, the hardened procfs implementation (used internally within
  `Reopen` and `Open(at)InRoot`) only protected against overmount attacks on
  systems with `openat2(2)` (Linux 5.6) or systems with `fsopen(2)` or
  `open_tree(2)` (Linux 4.18) and programs with privileges to use them (with
  some caveats about locked mounts that probably affect very few users). For
  other users, an attacker with the ability to create malicious mounts (on most
  systems, a sysadmin) could trick you into operating on files you didn't
  expect. This attack only really makes sense in the context of container
  runtime implementations.

  This was considered a reasonable trade-off, as the long-term intention was to
  get all users to just switch to [libpathrs][] if they wanted to use the safe
  `procfs` API (which had more extensive protections, and is what these new
  protections in `filepath-securejoin` are based on). However, as the API
  is now being exported it seems unwise to advertise the API as "safe" if we do
  not protect against known attacks.

  The procfs API will now be more protected against attackers on systems
  lacking the aforementioned protections. However, the most comprehensive of
  these protections effectively rely on [`statx(STATX_MNT_ID)`][statx.2] (Linux
  5.8). On older kernel versions, there is no effective protection (there is
  some minimal protection against non-`procfs` filesystem components but a
  sufficiently clever attacker can work around those). In addition,
  `STATX_MNT_ID` is vulnerable to mount ID reuse attacks by sufficiently
  motivated and privileged attackers -- this problem is mitigated with
  `STATX_MNT_ID_UNIQUE` (Linux 6.8) but that raises the minimum kernel version
  for more protection.

  The fact that these protections are quite limited despite needing a fair bit
  of extra code to handle was one of the primary reasons we did not initially
  implement this in `filepath-securejoin` ([libpathrs][] supports all of this,
  of course).

### Changed ###
- The procfs root file descriptor is no longer cached for the lifetime of the
  process. This kind of global file descriptor caching has caused security
  issues in container runtimes before (see [CVE-2024-21626][] for an example),
  and so it seems prudent to avoid it. This mirrors [a similar change made to
  libpathrs][libpathrs-pr204].

[CVE-2024-21626]: https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv
[libpathrs]: https://github.com/cyphar/libpathrs
[libpathrs-pr204]: https://github.com/cyphar/libpathrs/pull/204
[statx.2]: https://www.man7.org/linux/man-pages/man2/statx.2.html

## [0.4.1] - 2025-01-28 ##

### Fixed ###
- The restrictions added for `root` paths passed to `SecureJoin` in 0.4.0 was
  found to be too strict and caused some regressions when folks tried to
  update, so this restriction has been relaxed to only return an error if the
  path contains a `..` component. We still recommend users use `filepath.Clean`
  (and even `filepath.EvalSymlinks`) on the `root` path they are using, but at
  least you will no longer be punished for "trivial" unclean paths.

## [0.4.0] - 2025-01-13 ##

### Breaking ####
- `SecureJoin(VFS)` will now return an error if the provided `root` is not a
  `filepath.Clean`'d path.

  While it is ultimately the responsibility of the caller to ensure the root is
  a safe path to use, passing a path like `/symlink/..` as a root would result
  in the `SecureJoin`'d path being placed in `/` even though `/symlink/..`
  might be a different directory, and so we should more strongly discourage
  such usage.

  All major users of `securejoin.SecureJoin` already ensure that the paths they
  provide are safe (and this is ultimately a question of user error), but
  removing this foot-gun is probably a good idea. Of course, this is
  necessarily a breaking API change (though we expect no real users to be
  affected by it).

  Thanks to [Erik Sjölund](https://github.com/eriksjolund), who initially
  reported this issue as a possible security issue.

- `MkdirAll` and `MkdirHandle` now take an `os.FileMode`-style mode argument
  instead of a raw `unix.S_*`-style mode argument, which may cause compile-time
  type errors depending on how you use `filepath-securejoin`. For most users,
  there will be no change in behaviour aside from the type change (as the
  bottom `0o777` bits are the same in both formats, and most users are probably
  only using those bits).

  However, if you were using `unix.S_ISVTX` to set the sticky bit with
  `MkdirAll(Handle)` you will need to switch to `os.ModeSticky` otherwise you
  will get a runtime error with this update. In addition, the error message you
  will get from passing `unix.S_ISUID` and `unix.S_ISGID` will be different as
  they are treated as invalid bits now (note that previously passing said bits
  was also an error).

## [0.3.6] - 2024-12-17 ##

### Compatibility ###
- The minimum Go version requirement for `filepath-securejoin` is now Go 1.18
  (we use generics internally).

  For reference, `filepath-securejoin@v0.3.0` somewhat-arbitrarily bumped the
  Go version requirement to 1.21.

  While we did make some use of Go 1.21 stdlib features (and in principle Go
  versions <= 1.21 are no longer even supported by upstream anymore), some
  downstreams have complained that the version bump has meant that they have to
  do workarounds when backporting fixes that use the new `filepath-securejoin`
  API onto old branches. This is not an ideal situation, but since using this
  library is probably better for most downstreams than a hand-rolled
  workaround, we now have compatibility shims that allow us to build on older
  Go versions.
- Lower minimum version requirement for `golang.org/x/sys` to `v0.18.0` (we
  need the wrappers for `fsconfig(2)`), which should also make backporting
  patches to older branches easier.

## [0.3.5] - 2024-12-06 ##

### Fixed ###
- `MkdirAll` will now no longer return an `EEXIST` error if two racing
  processes are creating the same directory. We will still verify that the path
  is a directory, but this will avoid spurious errors when multiple threads or
  programs are trying to `MkdirAll` the same path. opencontainers/runc#4543

## [0.3.4] - 2024-10-09 ##

### Fixed ###
- Previously, some testing mocks we had resulted in us doing `import "testing"`
  in non-`_test.go` code, which made some downstreams like Kubernetes unhappy.
  This has been fixed. (#32)

## [0.3.3] - 2024-09-30 ##

### Fixed ###
- The mode and owner verification logic in `MkdirAll` has been removed. This
  was originally intended to protect against some theoretical attacks but upon
  further consideration these protections don't actually buy us anything and
  they were causing spurious errors with more complicated filesystem setups.
- The "is the created directory empty" logic in `MkdirAll` has also been
  removed. This was not causing us issues yet, but some pseudofilesystems (such
  as `cgroup`) create non-empty directories and so this logic would've been
  wrong for such cases.

## [0.3.2] - 2024-09-13 ##

### Changed ###
- Passing the `S_ISUID` or `S_ISGID` modes to `MkdirAllInRoot` will now return
  an explicit error saying that those bits are ignored by `mkdirat(2)`. In the
  past a different error was returned, but since the silent ignoring behaviour
  is codified in the man pages a more explicit error seems apt. While silently
  ignoring these bits would be the most compatible option, it could lead to
  users thinking their code sets these bits when it doesn't. Programs that need
  to deal with compatibility can mask the bits themselves. (#23, #25)

### Fixed ###
- If a directory has `S_ISGID` set, then all child directories will have
  `S_ISGID` set when created and a different gid will be used for any inode
  created under the directory. Previously, the "expected owner and mode"
  validation in `securejoin.MkdirAll` did not correctly handle this. We now
  correctly handle this case. (#24, #25)

## [0.3.1] - 2024-07-23 ##

### Changed ###
- By allowing `Open(at)InRoot` to opt-out of the extra work done by `MkdirAll`
  to do the necessary "partial lookups", `Open(at)InRoot` now does less work
  for both implementations (resulting in a many-fold decrease in the number of
  operations for `openat2`, and a modest improvement for non-`openat2`) and is
  far more guaranteed to match the correct `openat2(RESOLVE_IN_ROOT)`
  behaviour.
- We now use `readlinkat(fd, "")` where possible. For `Open(at)InRoot` this
  effectively just means that we no longer risk getting spurious errors during
  rename races. However, for our hardened procfs handler, this in theory should
  prevent mount attacks from tricking us when doing magic-link readlinks (even
  when using the unsafe host `/proc` handle). Unfortunately `Reopen` is still
  potentially vulnerable to those kinds of somewhat-esoteric attacks.

  Technically this [will only work on post-2.6.39 kernels][linux-readlinkat-emptypath]
  but it seems incredibly unlikely anyone is using `filepath-securejoin` on a
  pre-2011 kernel.

### Fixed ###
- Several improvements were made to the errors returned by `Open(at)InRoot` and
  `MkdirAll` when dealing with invalid paths under the emulated (ie.
  non-`openat2`) implementation. Previously, some paths would return the wrong
  error (`ENOENT` when the last component was a non-directory), and other paths
  would be returned as though they were acceptable (trailing-slash components
  after a non-directory would be ignored by `Open(at)InRoot`).

  These changes were done to match `openat2`'s behaviour and purely is a
  consistency fix (most users are going to be using `openat2` anyway).

[linux-readlinkat-emptypath]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=65cfc6722361570bfe255698d9cd4dccaf47570d

## [0.3.0] - 2024-07-11 ##

### Added ###
- A new set of `*os.File`-based APIs have been added. These are adapted from
  [libpathrs][] and we strongly suggest using them if possible (as they provide
  far more protection against attacks than `SecureJoin`):

   - `Open(at)InRoot` resolves a path inside a rootfs and returns an `*os.File`
     handle to the path. Note that the handle returned is an `O_PATH` handle,
     which cannot be used for reading or writing (as well as some other
     operations -- [see open(2) for more details][open.2])

   - `Reopen` takes an `O_PATH` file handle and safely re-opens it to upgrade
     it to a regular handle. This can also be used with non-`O_PATH` handles,
     but `O_PATH` is the most obvious application.

   - `MkdirAll` is an implementation of `os.MkdirAll` that is safe to use to
     create a directory tree within a rootfs.

  As these are new APIs, they may change in the future. However, they should be
  safe to start migrating to as we have extensive tests ensuring they behave
  correctly and are safe against various races and other attacks.

[libpathrs]: https://github.com/cyphar/libpathrs
[open.2]: https://www.man7.org/linux/man-pages/man2/open.2.html

## [0.2.5] - 2024-05-03 ##

### Changed ###
- Some minor changes were made to how lexical components (like `..` and `.`)
  are handled during path generation in `SecureJoin`. There is no behaviour
  change as a result of this fix (the resulting paths are the same).

### Fixed ###
- The error returned when we hit a symlink loop now references the correct
  path. (#10)

## [0.2.4] - 2023-09-06 ##

### Security ###
- This release fixes a potential security issue in filepath-securejoin when
  used on Windows ([GHSA-6xv5-86q9-7xr8][], which could be used to generate
  paths outside of the provided rootfs in certain cases), as well as improving
  the overall behaviour of filepath-securejoin when dealing with Windows paths
  that contain volume names. Thanks to Paulo Gomes for discovering and fixing
  these issues.

### Fixed ###
- Switch to GitHub Actions for CI so we can test on Windows as well as Linux
  and MacOS.

[GHSA-6xv5-86q9-7xr8]: https://github.com/advisories/GHSA-6xv5-86q9-7xr8

## [0.2.3] - 2021-06-04 ##

### Changed ###
- Switch to Go 1.13-style `%w` error wrapping, letting us drop the dependency
  on `github.com/pkg/errors`.

## [0.2.2] - 2018-09-05 ##

### Changed ###
- Use `syscall.ELOOP` as the base error for symlink loops, rather than our own
  (internal) error. This allows callers to more easily use `errors.Is` to check
  for this case.

## [0.2.1] - 2018-09-05 ##

### Fixed ###
- Use our own `IsNotExist` implementation, which lets us handle `ENOTDIR`
  properly within `SecureJoin`.

## [0.2.0] - 2017-07-19 ##

We now have 100% test coverage!

### Added ###
- Add a `SecureJoinVFS` API that can be used for mocking (as we do in our new
  tests) or for implementing custom handling of lookup operations (such as for
  rootless containers, where work is necessary to access directories with weird
  modes because we don't have `CAP_DAC_READ_SEARCH` or `CAP_DAC_OVERRIDE`).

## 0.1.0 - 2017-07-19

This is our first release of `github.com/cyphar/filepath-securejoin`,
containing a full implementation with a coverage of 93.5% (the only missing
cases are the error cases, which are hard to mocktest at the moment).

[Unreleased]: https://github.com/cyphar/filepath-securejoin/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/cyphar/filepath-securejoin/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/cyphar/filepath-securejoin/compare/v0.3.6...v0.4.0
[0.3.6]: https://github.com/cyphar/filepath-securejoin/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/cyphar/filepath-securejoin/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/cyphar/filepath-securejoin/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/cyphar/filepath-securejoin/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/cyphar/filepath-securejoin/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/cyphar/filepath-securejoin/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/cyphar/filepath-securejoin/compare/v0.2.5...v0.3.0
[0.2.5]: https://github.com/cyphar/filepath-securejoin/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/cyphar/filepath-securejoin/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/cyphar/filepath-securejoin/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/cyphar/filepath-securejoin/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/cyphar/filepath-securejoin/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/cyphar/filepath-securejoin/compare/v0.1.0...v0.2.0
