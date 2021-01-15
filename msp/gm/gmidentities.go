/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	msp2 "github.com/hyperledger/fabric/msp"
	"go.uber.org/zap/zapcore"

	"github.com/tjfoc/gmsm/sm2"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
)


//TODO
type identity struct {
	// id contains the identifier (MSPID and identity identifier) for this instance
	id *msp2.IdentityIdentifier

	// cert contains the x.509 certificate that signs the public key of this instance
	cert *sm2.Certificate

	// this is the public key of this instance
	pk bccsp.Key

	// reference to the MSP that "owns" this identity
	msp *gmmsp

	// validationMutex is used to synchronise memory operation
	// over validated and validationErr
	validationMutex sync.Mutex

	// validated is true when the validateIdentity function
	// has been called on this instance
	validated bool

	// validationErr contains the validation error for this
	// instance. It can be read if validated is true
	validationErr error
}

type signingidentity struct {
	// we embed everything from a base identity
	identity

	// signer corresponds to the object that can produce signatures from this identity
	signer crypto.Signer
}

// Sign produces a signature over msg, signed by this instance
func (id *signingidentity) Sign(msg []byte) ([]byte, error) {
	//mspIdentityLogger.Infof("Signing message")

	// Compute Hash
	hashOpt, err := id.getHashOpt(id.msp.cryptoConfig.SignatureHashFamily)
	if err != nil {
		return nil, errors.WithMessage(err, "failed getting hash function options")
	}

	digest, err := id.msp.bccsp.Hash(msg, hashOpt)
	if err != nil {
		return nil, errors.WithMessage(err, "failed computing digest")
	}

	if len(msg) < 32 {
		mspLogger.Debugf("Sign: plaintext: %X \n", msg)
	} else {
		mspLogger.Debugf("Sign: plaintext: %X...%X \n", msg[0:16], msg[len(msg)-16:])
	}
	mspLogger.Debugf("Sign: digest: %X \n", digest)

	// Sign
	return id.signer.Sign(rand.Reader, msg, nil)
}

// GetPublicVersion returns the public version of this identity,
// namely, the one that is only able to verify messages and not sign them
func (id *signingidentity) GetPublicVersion() msp2.Identity {
	return &id.identity
}

func newIdentity(cert *sm2.Certificate, pk bccsp.Key, gmmsp *gmmsp) (msp2.Identity, error) {
	//if msp2.mspIdentityLogger.IsEnabledFor(zapcore.DebugLevel) {
	//	msp2.mspIdentityLogger.Debugf("Creating identity instance for cert %s", (cert))
	//}

	// Sanitize first the certificate
	cert, err := gmmsp.sanitizeCert(cert)
	if err != nil {
		return nil, err
	}

	// Compute identity identifier

	// Use the hash of the identity's certificate as id in the IdentityIdentifier
	hashOpt, err := bccsp.GetHashOpt(gmmsp.cryptoConfig.IdentityIdentifierHashFunction)
	if err != nil {
		return nil, errors.WithMessage(err, "failed getting hash function options")
	}

	digest, err := gmmsp.bccsp.Hash(cert.Raw, hashOpt)
	if err != nil {
		return nil, errors.WithMessage(err, "failed hashing raw certificate to compute the id of the IdentityIdentifier")
	}

	id := &msp2.IdentityIdentifier{
		Mspid: gmmsp.name,
		Id:    hex.EncodeToString(digest)}

	return &identity{id: id, cert: cert, pk: pk, msp: gmmsp}, nil
}

// ExpiresAt returns the time at which the Identity expires.
func (id *identity) ExpiresAt() time.Time {
	return id.cert.NotAfter
}

// SatisfiesPrincipal returns nil if this instance matches the supplied principal or an error otherwise
func (id *identity) SatisfiesPrincipal(principal *msp.MSPPrincipal) error {
	return id.msp.SatisfiesPrincipal(id, principal)
}

// GetIdentifier returns the identifier (MSPID/IDID) for this instance
func (id *identity) GetIdentifier() *msp2.IdentityIdentifier {
	return id.id
}

// GetMSPIdentifier returns the MSP identifier for this instance
func (id *identity) GetMSPIdentifier() string {
	return id.id.Mspid
}

// Validate returns nil if this instance is a valid identity or an error otherwise
func (id *identity) Validate() error {
	return id.msp.Validate(id)
}

// GetOrganizationalUnits returns the OU for this instance
func (id *identity) GetOrganizationalUnits() []*msp2.OUIdentifier {
	if id.cert == nil {
		return nil
	}

	cid, err := id.msp.getCertificationChainIdentifier(id)
	if err != nil {
		return nil
	}

	var res []*msp2.OUIdentifier
	for _, unit := range id.cert.Subject.OrganizationalUnit {
		res = append(res, &msp2.OUIdentifier{
			OrganizationalUnitIdentifier: unit,
			CertifiersIdentifier:         cid,
		})
	}

	return res
}

// Anonymous returns true if this identity provides anonymity
func (id *identity) Anonymous() bool {
	return false
}


// Verify checks against a signature and a message
// to determine whether this identity produced the
// signature; it returns nil if so or an error otherwise
func (id *identity) Verify(msg []byte, sig []byte) error {
	hashOpt, err := id.getHashOpt(id.msp.cryptoConfig.SignatureHashFamily)
	if err != nil {
		return errors.WithMessage(err, "failed getting hash function options")
	}

	digest, err := id.msp.bccsp.Hash(msg, hashOpt)
	if err != nil {
		return errors.WithMessage(err, "failed computing digest")
	}

	if mspLogger.IsEnabledFor(zapcore.DebugLevel) {
		mspLogger.Debugf("Verify: digest = %s", hex.Dump(digest))
		mspLogger.Debugf("Verify: sig = %s", hex.Dump(sig))
	}
	valid, err := id.msp.bccsp.Verify(id.pk, sig, msg, nil)
	if err != nil {
		return errors.WithMessage(err, "could not determine the validity of the signature")
	} else if !valid {
		return errors.New("The signature is invalid")
	}

	return nil
}

// Serialize returns a byte array representation of this identity
func (id *identity) Serialize() ([]byte, error) {
	pb := &pem.Block{Bytes: id.cert.Raw, Type: "CERTIFICATE"}
	pemBytes := pem.EncodeToMemory(pb)
	if pemBytes == nil {
		return nil, errors.New("encoding of identity failed")
	}

	// We serialize identities by prepending the MSPID and appending the ASN.1 DER content of the cert
	sId := &msp.SerializedIdentity{Mspid: id.id.Mspid, IdBytes: pemBytes}
	idBytes, err := proto.Marshal(sId)
	if err != nil {
		return nil, errors.Wrapf(err, "could not marshal a SerializedIdentity structure for identity %s", id.id)
	}

	return idBytes, nil
}

func (id *identity) getHashOpt(hashFamily string) (bccsp.HashOpts, error) {
	switch hashFamily {
	case bccsp.SHA2:
		return bccsp.GetHashOpt(bccsp.SHA256)
	case bccsp.SHA3:
		return bccsp.GetHashOpt(bccsp.SHA3_256)
	case bccsp.GMSM3:
		return bccsp.GetHashOpt(bccsp.GMSM3)
	}
	return nil, errors.Errorf("hash familiy not recognized [%s]", hashFamily)
}

func newSigningIdentity(cert *sm2.Certificate, pk bccsp.Key, signer crypto.Signer, gmmsp *gmmsp) (msp2.SigningIdentity, error) {
	//mspIdentityLogger.Infof("Creating signing identity instance for ID %s", id)
	mspId, err := newIdentity(cert, pk, gmmsp)
	if err != nil {
		return nil, err
	}
	return &signingidentity{
		identity: identity{
			id:   mspId.(*identity).id,
			cert: mspId.(*identity).cert,
			msp:  mspId.(*identity).msp,
			pk:   mspId.(*identity).pk,
		},
		signer: signer,
	}, nil
}


