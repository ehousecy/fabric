/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto"
	"io"

	"github.com/hyperledger/fabric/bccsp"
)

// bccspCryptoSigner is the BCCSP-based implementation of a crypto.Signer
type gmCryptoSigner struct {
	csp bccsp.BCCSP
	key bccsp.Key
	pk  interface{}
}

// Public returns the public key corresponding to the opaque,
// private key.
func (s *gmCryptoSigner) Public() crypto.PublicKey {
	return s.pk
}

func (s *gmCryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.csp.Sign(s.key, digest, opts)
}
