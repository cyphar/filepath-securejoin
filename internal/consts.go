// SPDX-License-Identifier: MPL-2.0

// Copyright (C) 2024-2025 Aleksa Sarai <cyphar@cyphar.com>
// Copyright (C) 2024-2025 SUSE LLC
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package internal

// MaxSymlinkLimit is the maximum number of symlinks that can be encountered
// during a single lookup before returning -ELOOP. At time of writing, Linux
// has an internal limit of 40.
const MaxSymlinkLimit = 255
