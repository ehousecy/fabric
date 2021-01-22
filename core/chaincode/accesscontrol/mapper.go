/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package accesscontrol

import (
	"context"
	"crypto/x509"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmtls/gmcredentials"
	"google.golang.org/grpc/credentials"
	"sync"
	"time"

	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/hyperledger/fabric/common/util"
	"google.golang.org/grpc/peer"
)

var ttl = time.Minute * 10

type certHash string

type KeyGenFunc func() (*tlsgen.CertKeyPair, error)

type certMapper struct {
	keyGen KeyGenFunc
	sync.RWMutex
	m map[certHash]string
}

func newCertMapper(keyGen KeyGenFunc) *certMapper {
	return &certMapper{
		keyGen: keyGen,
		m:      make(map[certHash]string),
	}
}

func (r *certMapper) lookup(h certHash) string {
	r.RLock()
	defer r.RUnlock()
	return r.m[h]
}

func (r *certMapper) register(hash certHash, name string) {
	r.Lock()
	defer r.Unlock()
	r.m[hash] = name
	time.AfterFunc(ttl, func() {
		r.purge(hash)
	})
}

func (r *certMapper) purge(hash certHash) {
	r.Lock()
	defer r.Unlock()
	delete(r.m, hash)
}

func (r *certMapper) genCert(name string) (*tlsgen.CertKeyPair, error) {
	keyPair, err := r.keyGen()
	if err != nil {
		return nil, err
	}
	switch keyPair.TLSCert.(type) {
	case *x509.Certificate:
		hash := util.ComputeSHA256(keyPair.TLSCert.(*x509.Certificate).Raw)
		r.register(certHash(hash), name)
	case *sm2.Certificate:
		hash := util.ComputeSHA256(keyPair.TLSCert.(*sm2.Certificate).Raw)
		r.register(certHash(hash), name)
	default:
		panic("UnSupport certificate type")
	}

	return keyPair, nil
}

// ExtractCertificateHash extracts the hash of the certificate from the stream
func extractCertificateHashFromContext(ctx context.Context) []byte {
	pr, extracted := peer.FromContext(ctx)
	if !extracted {
		return nil
	}
	authInfo := pr.AuthInfo
	if authInfo == nil {
		return nil
	}
	switch authInfo.(type) {
	case credentials.TLSInfo:
		tlsInfo, isTLSConn := authInfo.(credentials.TLSInfo)
		if !isTLSConn {
			return nil
		}
		certs := tlsInfo.State.PeerCertificates
		if len(certs) == 0 {
			return nil
		}
		raw := certs[0].Raw
		if len(raw) == 0 {
			return nil
		}
		return util.ComputeSHA256(raw)
	case gmcredentials.AuthInfo:
		tlsInfo, isTLSConn := authInfo.(gmcredentials.TLSInfo)
		if !isTLSConn {
			return nil
		}
		certs := tlsInfo.State.PeerCertificates
		if len(certs) == 0 {
			return nil
		}
		raw := certs[0].Raw
		if len(raw) == 0 {
			return nil
		}
		return util.ComputeSHA256(raw)
	default:
		panic("unsupport credential type")
	}

}
