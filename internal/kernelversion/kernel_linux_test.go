// SPDX-License-Identifier: Apache-2.0
/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   File copied and customized based on
   https://github.com/moby/moby/tree/v20.10.14/profiles/seccomp/kernel_linux_test.go

   File copied from
   https://github.com/opencontainers/runc/blob/v1.3.0/libcontainer/system/kernelversion/kernel_linux_test.go
   and updated to use testify assertions.

   (Aleksa: Maybe we should put this somewhere more useful for everyone?)
*/

package kernelversion

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetKernelVersion(t *testing.T) {
	version, err := getKernelVersion()
	require.NoError(t, err)
	if assert.NotNil(t, version, "version must not be nil") {
		assert.NotZero(t, version.Kernel, "kernel major version must not be nil")
	}
}

func TestParseRelease(t *testing.T) {
	tests := []struct {
		in        string
		out       KernelVersion
		expectErr bool
		errString string
	}{
		{in: "3.8", out: KernelVersion{Kernel: 3, Major: 8}},
		{in: "3.8.0", out: KernelVersion{Kernel: 3, Major: 8}},
		{in: "3.8.0-19-generic", out: KernelVersion{Kernel: 3, Major: 8}},
		{in: "3.4.54.longterm-1", out: KernelVersion{Kernel: 3, Major: 4}},
		{in: "3.10.0-862.2.3.el7.x86_64", out: KernelVersion{Kernel: 3, Major: 10}},
		{in: "3.12.8tag", out: KernelVersion{Kernel: 3, Major: 12}},
		{in: "3.12-1-amd64", out: KernelVersion{Kernel: 3, Major: 12}},
		{in: "3.12foobar", out: KernelVersion{Kernel: 3, Major: 12}},
		{in: "99.999.999-19-generic", out: KernelVersion{Kernel: 99, Major: 999}},
		{in: "", expectErr: true, errString: `failed to parse kernel version "": EOF`},
		{in: "3", expectErr: true, errString: `failed to parse kernel version "3": unexpected EOF`},
		{in: "3.", expectErr: true, errString: `failed to parse kernel version "3.": EOF`},
		{in: "3a", expectErr: true, errString: `failed to parse kernel version "3a": input does not match format`},
		{in: "3.a", expectErr: true, errString: `failed to parse kernel version "3.a": expected integer`},
		{in: "a", expectErr: true, errString: `failed to parse kernel version "a": expected integer`},
		{in: "a.a", expectErr: true, errString: `failed to parse kernel version "a.a": expected integer`},
		{in: "a.a.a-a", expectErr: true, errString: `failed to parse kernel version "a.a.a-a": expected integer`},
		{in: "-3", expectErr: true, errString: `failed to parse kernel version "-3": expected integer`},
		{in: "-3.", expectErr: true, errString: `failed to parse kernel version "-3.": expected integer`},
		{in: "-3.8", expectErr: true, errString: `failed to parse kernel version "-3.8": expected integer`},
		{in: "-3.-8", expectErr: true, errString: `failed to parse kernel version "-3.-8": expected integer`},
		{in: "3.-8", expectErr: true, errString: `failed to parse kernel version "3.-8": expected integer`},
	}
	for _, tc := range tests {
		tc := tc // copy iterator
		t.Run(tc.in, func(t *testing.T) {
			version, err := parseRelease(tc.in)
			if tc.expectErr {
				require.Errorf(t, err, "parseRelease(%q)", tc.in)
				require.ErrorContainsf(t, err, tc.errString, "parseRelease(%q)", tc.in)
			} else {
				require.NoError(t, err, "parseRelease(%q)", tc.in)
				if assert.NotNil(t, version, "version must not be nil") {
					assert.Equalf(t, tc.out.Kernel, version.Kernel, "parseRelease(%q) Kernel mismatch", tc.in)
					assert.Equalf(t, tc.out.Major, version.Major, "parseRelease(%q) Major mismatch", tc.in)
				}
			}
		})
	}
}

func TestGreaterEqualThan(t *testing.T) {
	// Get the current kernel version, so that we can make test relative to that
	v, err := getKernelVersion()
	require.NoError(t, err, "getKernelVersion")

	tests := []struct {
		doc      string
		in       KernelVersion
		expected bool
	}{
		{
			doc:      "same version",
			in:       KernelVersion{v.Kernel, v.Major},
			expected: true,
		},
		{
			doc:      "kernel minus one",
			in:       KernelVersion{v.Kernel - 1, v.Major},
			expected: true,
		},
		{
			doc:      "kernel plus one",
			in:       KernelVersion{v.Kernel + 1, v.Major},
			expected: false,
		},
		{
			doc:      "major plus one",
			in:       KernelVersion{v.Kernel, v.Major + 1},
			expected: false,
		},
	}
	for _, tc := range tests {
		tc := tc // copy iterator
		t.Run(tc.doc+": "+tc.in.String(), func(t *testing.T) {
			ok, err := GreaterEqualThan(tc.in)
			require.NoErrorf(t, err, "GreaterEqualThan(%#v)", tc.in)
			assert.Equal(t, tc.expected, ok)
		})
	}
}
