// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build js
// +build js

package x509

func loadSystemRoots() (*CertPool, error) {
	roots := NewCertPool()
	return roots, nil
}

func (c *Certificate) systemVerify(opts *VerifyOptions) (chains [][]*Certificate, err error) {
	return nil, nil
}
