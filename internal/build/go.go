// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build !tinygo

// Package build is used to hold code related to build tags. This is often
// necessary because the go/build package is not available in TinyGo.
package build

// TinyGo indicates whether the build was created with TinyGo.
const TinyGo = false
