/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"context"
	"github.com/tjfoc/gmtls/gmcredentials"

	"github.com/hyperledger/fabric/common/util"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func certHashFromRawCert(rawCert []byte) []byte {
	if len(rawCert) == 0 {
		return nil
	}
	return util.ComputeSHA256(rawCert)
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
