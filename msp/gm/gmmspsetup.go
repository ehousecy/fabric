/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"bytes"
	"crypto/x509/pkix"
	"fmt"
	"github.com/hyperledger/fabric/msp"
	"github.com/tjfoc/gmsm/sm2"
	"time"

	"github.com/golang/protobuf/proto"
	m "github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
)

func (gmmsp *gmmsp) getCertifiersIdentifier(certRaw []byte) ([]byte, error) {
	// 1. check that certificate is registered in msp.rootCerts or msp.intermediateCerts
	cert, err := gmmsp.getCertFromPem(certRaw)
	if err != nil {
		return nil, fmt.Errorf("Failed getting certificate for [%v]: [%s]", certRaw, err)
	}

	// 2. Sanitize it to ensure like for like comparison
	cert, err = gmmsp.sanitizeCert(cert)
	if err != nil {
		return nil, fmt.Errorf("sanitizeCert failed %s", err)
	}

	found := false
	root := false
	// Search among root certificates
	for _, v := range gmmsp.rootCerts {
		if v.(*identity).cert.Equal(cert) {
			found = true
			root = true
			break
		}
	}
	if !found {
		// Search among root intermediate certificates
		for _, v := range gmmsp.intermediateCerts {
			if v.(*identity).cert.Equal(cert) {
				found = true
				break
			}
		}
	}
	if !found {
		// Certificate not valid, reject configuration
		return nil, fmt.Errorf("Failed adding OU. Certificate [%v] not in root or intermediate certs.", cert)
	}

	// 3. get the certification path for it
	var certifiersIdentifier []byte
	var chain []*sm2.Certificate
	if root {
		chain = []*sm2.Certificate{cert}
	} else {
		chain, err = gmmsp.getValidationChain(cert, true)
		if err != nil {
			return nil, fmt.Errorf("Failed computing validation chain for [%v]. [%s]", cert, err)
		}
	}

	// 4. compute the hash of the certification path
	certifiersIdentifier, err = gmmsp.getCertificationChainIdentifierFromChain(chain)
	if err != nil {
		return nil, fmt.Errorf("Failed computing Certifiers Identifier for [%v]. [%s]", certRaw, err)
	}

	return certifiersIdentifier, nil

}

func (gmmsp *gmmsp) setupCrypto(conf *m.FabricMSPConfig) error {
	gmmsp.cryptoConfig = conf.CryptoConfig
	if gmmsp.cryptoConfig == nil {
		// Move to defaults
		/*mspLogger.Debugf("msp.cryptoConfig----,%v", msp.cryptoConfig)*/
		gmmsp.cryptoConfig = &m.FabricCryptoConfig{
			SignatureHashFamily:            bccsp.GMSM3,
			IdentityIdentifierHashFunction: bccsp.SHA256,
		}
		mspLogger.Debugf("GM CryptoConfig was nil. Move to defaults.")
	}
	/*mspLogger.Debugf("msp.cryptoConfig.SignatureHashFamily----,%v", msp.cryptoConfig.SignatureHashFamily)*/
	if gmmsp.cryptoConfig.SignatureHashFamily == "" {
		gmmsp.cryptoConfig.SignatureHashFamily = bccsp.GMSM3
		mspLogger.Debugf("CryptoConfig.SignatureHashFamily was nil. Move to defaults.")
	}
	if gmmsp.cryptoConfig.IdentityIdentifierHashFunction == "" {
		gmmsp.cryptoConfig.IdentityIdentifierHashFunction = bccsp.SHA256
		mspLogger.Debugf("CryptoConfig.IdentityIdentifierHashFunction was nil. Move to defaults.")
	}

	return nil
}

func (gmmsp *gmmsp) setupCAs(conf *m.FabricMSPConfig) error {
	// make and fill the set of CA certs - we expect them to be there
	if len(conf.RootCerts) == 0 {
		return errors.New("expected at least one CA certificate")
	}

	// pre-create the verify options with roots and intermediates.
	// This is needed to make certificate sanitation working.
	// Recall that sanitization is applied also to root CA and intermediate
	// CA certificates. After their sanitization is done, the opts
	// will be recreated using the sanitized certs.
	gmmsp.opts = &sm2.VerifyOptions{Roots: sm2.NewCertPool(), Intermediates: sm2.NewCertPool()}
	for _, v := range conf.RootCerts {
		cert, err := gmmsp.getCertFromPem(v)
		if err != nil {
			return err
		}
		gmmsp.opts.Roots.AddCert(cert)
	}
	for _, v := range conf.IntermediateCerts {
		cert, err := gmmsp.getCertFromPem(v)
		if err != nil {
			return err
		}
		gmmsp.opts.Intermediates.AddCert(cert)
	}

	// Load root and intermediate CA identities
	// Recall that when an identity is created, its certificate gets sanitized
	gmmsp.rootCerts = make([]msp.Identity, len(conf.RootCerts))
	for i, trustedCert := range conf.RootCerts {
		id, _, err := gmmsp.getIdentityFromConf(trustedCert)
		if err != nil {
			return err
		}

		gmmsp.rootCerts[i] = id
	}

	// make and fill the set of intermediate certs (if present)
	gmmsp.intermediateCerts = make([]msp.Identity, len(conf.IntermediateCerts))
	for i, trustedCert := range conf.IntermediateCerts {
		id, _, err := gmmsp.getIdentityFromConf(trustedCert)
		if err != nil {
			return err
		}

		gmmsp.intermediateCerts[i] = id
	}

	// root CA and intermediate CA certificates are sanitized, they can be re-imported
	gmmsp.opts = &sm2.VerifyOptions{Roots: sm2.NewCertPool(), Intermediates: sm2.NewCertPool()}
	for _, id := range gmmsp.rootCerts {
		gmmsp.opts.Roots.AddCert(id.(*identity).cert)
	}
	for _, id := range gmmsp.intermediateCerts {
		gmmsp.opts.Intermediates.AddCert(id.(*identity).cert)
	}

	return nil
}

func (gmmsp *gmmsp) setupAdmins(conf *m.FabricMSPConfig) error {
	return gmmsp.internalSetupAdmin(conf)
}

func (gmmsp *gmmsp) setupAdminsPreV142(conf *m.FabricMSPConfig) error {
	// make and fill the set of admin certs (if present)
	gmmsp.admins = make([]msp.Identity, len(conf.Admins))
	for i, admCert := range conf.Admins {
		id, _, err := gmmsp.getIdentityFromConf(admCert)
		if err != nil {
			return err
		}

		gmmsp.admins[i] = id
	}

	return nil
}

func (gmmsp *gmmsp) setupAdminsV142(conf *m.FabricMSPConfig) error {
	// make and fill the set of admin certs (if present)
	if err := gmmsp.setupAdminsPreV142(conf); err != nil {
		return err
	}

	if len(gmmsp.admins) == 0 && (!gmmsp.ouEnforcement || gmmsp.adminOU == nil) {
		return errors.New("administrators must be declared when no admin ou classification is set")
	}

	return nil
}

func (gmmsp *gmmsp) setupCRLs(conf *m.FabricMSPConfig) error {
	// setup the CRL (if present)
	gmmsp.CRL = make([]*pkix.CertificateList, len(conf.RevocationList))
	for i, crlbytes := range conf.RevocationList {
		crl, err := sm2.ParseCRL(crlbytes)
		if err != nil {
			return errors.Wrap(err, "could not parse RevocationList")
		}

		// TODO: pre-verify the signature on the CRL and create a map
		//       of CA certs to respective CRLs so that later upon
		//       validation we can already look up the CRL given the
		//       chain of the certificate to be validated

		gmmsp.CRL[i] = crl
	}

	return nil
}

func (gmmsp *gmmsp) finalizeSetupCAs() error {
	// ensure that our CAs are properly formed and that they are valid
	for _, id := range append(append([]msp.Identity{}, gmmsp.rootCerts...), gmmsp.intermediateCerts...) {
		if !id.(*identity).cert.IsCA {
			return errors.Errorf("CA Certificate did not have the CA attribute, (SN: %x)", id.(*identity).cert.SerialNumber)
		}
		if _, err := getSubjectKeyIdentifierFromCert(id.(*identity).cert); err != nil {
			return errors.WithMessagef(err, "CA Certificate problem with Subject Key Identifier extension, (SN: %x)", id.(*identity).cert.SerialNumber)
		}

		if err := gmmsp.validateCAIdentity(id.(*identity)); err != nil {
			return errors.WithMessagef(err, "CA Certificate is not valid, (SN: %s)", id.(*identity).cert.SerialNumber)
		}
	}

	// populate certificationTreeInternalNodesMap to mark the internal nodes of the
	// certification tree
	gmmsp.certificationTreeInternalNodesMap = make(map[string]bool)
	for _, id := range append([]msp.Identity{}, gmmsp.intermediateCerts...) {
		chain, err := gmmsp.getUniqueValidationChain(id.(*identity).cert, gmmsp.getValidityOptsForCert(id.(*identity).cert))
		if err != nil {
			return errors.WithMessagef(err, "failed getting validation chain, (SN: %s)", id.(*identity).cert.SerialNumber)
		}

		// Recall chain[0] is id.(*identity).id so it does not count as a parent
		for i := 1; i < len(chain); i++ {
			gmmsp.certificationTreeInternalNodesMap[string(chain[i].Raw)] = true
		}
	}

	return nil
}

func (gmmsp *gmmsp) setupNodeOUs(config *m.FabricMSPConfig) error {
	if config.FabricNodeOus != nil {

		gmmsp.ouEnforcement = config.FabricNodeOus.Enable

		if config.FabricNodeOus.ClientOuIdentifier == nil || len(config.FabricNodeOus.ClientOuIdentifier.OrganizationalUnitIdentifier) == 0 {
			return errors.New("Failed setting up NodeOUs. ClientOU must be different from nil.")
		}

		if config.FabricNodeOus.PeerOuIdentifier == nil || len(config.FabricNodeOus.PeerOuIdentifier.OrganizationalUnitIdentifier) == 0 {
			return errors.New("Failed setting up NodeOUs. PeerOU must be different from nil.")
		}

		// ClientOU
		gmmsp.clientOU = &msp.OUIdentifier{OrganizationalUnitIdentifier: config.FabricNodeOus.ClientOuIdentifier.OrganizationalUnitIdentifier}
		if len(config.FabricNodeOus.ClientOuIdentifier.Certificate) != 0 {
			certifiersIdentifier, err := gmmsp.getCertifiersIdentifier(config.FabricNodeOus.ClientOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			gmmsp.clientOU.CertifiersIdentifier = certifiersIdentifier
		}

		// PeerOU
		gmmsp.peerOU = &msp.OUIdentifier{OrganizationalUnitIdentifier: config.FabricNodeOus.PeerOuIdentifier.OrganizationalUnitIdentifier}
		if len(config.FabricNodeOus.PeerOuIdentifier.Certificate) != 0 {
			certifiersIdentifier, err := gmmsp.getCertifiersIdentifier(config.FabricNodeOus.PeerOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			gmmsp.peerOU.CertifiersIdentifier = certifiersIdentifier
		}

	} else {
		gmmsp.ouEnforcement = false
	}

	return nil
}

func (gmmsp *gmmsp) setupNodeOUsV142(config *m.FabricMSPConfig) error {
	if config.FabricNodeOus == nil {
		gmmsp.ouEnforcement = false
		return nil
	}

	gmmsp.ouEnforcement = config.FabricNodeOus.Enable

	counter := 0
	// ClientOU
	if config.FabricNodeOus.ClientOuIdentifier != nil {
		gmmsp.clientOU = &msp.OUIdentifier{OrganizationalUnitIdentifier: config.FabricNodeOus.ClientOuIdentifier.OrganizationalUnitIdentifier}
		if len(config.FabricNodeOus.ClientOuIdentifier.Certificate) != 0 {
			certifiersIdentifier, err := gmmsp.getCertifiersIdentifier(config.FabricNodeOus.ClientOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			gmmsp.clientOU.CertifiersIdentifier = certifiersIdentifier
		}
		counter++
	} else {
		gmmsp.clientOU = nil
	}

	// PeerOU
	if config.FabricNodeOus.PeerOuIdentifier != nil {
		gmmsp.peerOU = &msp.OUIdentifier{OrganizationalUnitIdentifier: config.FabricNodeOus.PeerOuIdentifier.OrganizationalUnitIdentifier}
		if len(config.FabricNodeOus.PeerOuIdentifier.Certificate) != 0 {
			certifiersIdentifier, err := gmmsp.getCertifiersIdentifier(config.FabricNodeOus.PeerOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			gmmsp.peerOU.CertifiersIdentifier = certifiersIdentifier
		}
		counter++
	} else {
		gmmsp.peerOU = nil
	}

	// AdminOU
	if config.FabricNodeOus.AdminOuIdentifier != nil {
		gmmsp.adminOU = &msp.OUIdentifier{OrganizationalUnitIdentifier: config.FabricNodeOus.AdminOuIdentifier.OrganizationalUnitIdentifier}
		if len(config.FabricNodeOus.AdminOuIdentifier.Certificate) != 0 {
			certifiersIdentifier, err := gmmsp.getCertifiersIdentifier(config.FabricNodeOus.AdminOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			gmmsp.adminOU.CertifiersIdentifier = certifiersIdentifier
		}
		counter++
	} else {
		gmmsp.adminOU = nil
	}

	// OrdererOU
	if config.FabricNodeOus.OrdererOuIdentifier != nil {
		gmmsp.ordererOU = &msp.OUIdentifier{OrganizationalUnitIdentifier: config.FabricNodeOus.OrdererOuIdentifier.OrganizationalUnitIdentifier}
		if len(config.FabricNodeOus.OrdererOuIdentifier.Certificate) != 0 {
			certifiersIdentifier, err := gmmsp.getCertifiersIdentifier(config.FabricNodeOus.OrdererOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			gmmsp.ordererOU.CertifiersIdentifier = certifiersIdentifier
		}
		counter++
	} else {
		gmmsp.ordererOU = nil
	}

	if counter == 0 {
		// Disable NodeOU
		gmmsp.ouEnforcement = false
	}

	return nil
}

func (gmmsp *gmmsp) setupSigningIdentity(conf *m.FabricMSPConfig) error {
	if conf.SigningIdentity != nil {
		sid, err := gmmsp.getSigningIdentityFromConf(conf.SigningIdentity)
		if err != nil {
			return err
		}

		expirationTime := sid.ExpiresAt()
		now := time.Now()
		if expirationTime.After(now) {
			mspLogger.Debug("Signing identity expires at", expirationTime)
		} else if expirationTime.IsZero() {
			mspLogger.Debug("Signing identity has no known expiration time")
		} else {
			return errors.Errorf("signing identity expired %v ago", now.Sub(expirationTime))
		}

		gmmsp.signer = sid
	}

	return nil
}

func (gmmsp *gmmsp) setupOUs(conf *m.FabricMSPConfig) error {
	gmmsp.ouIdentifiers = make(map[string][][]byte)
	for _, ou := range conf.OrganizationalUnitIdentifiers {

		certifiersIdentifier, err := gmmsp.getCertifiersIdentifier(ou.Certificate)
		if err != nil {
			return errors.WithMessagef(err, "failed getting certificate for [%v]", ou)
		}

		// Check for duplicates
		found := false
		for _, id := range gmmsp.ouIdentifiers[ou.OrganizationalUnitIdentifier] {
			if bytes.Equal(id, certifiersIdentifier) {
				mspLogger.Warningf("Duplicate found in ou identifiers [%s, %v]", ou.OrganizationalUnitIdentifier, id)
				found = true
				break
			}
		}

		if !found {
			// No duplicates found, add it
			gmmsp.ouIdentifiers[ou.OrganizationalUnitIdentifier] = append(
				gmmsp.ouIdentifiers[ou.OrganizationalUnitIdentifier],
				certifiersIdentifier,
			)
		}
	}

	return nil
}

func (gmmsp *gmmsp) setupTLSCAs(conf *m.FabricMSPConfig) error {

	opts := &sm2.VerifyOptions{Roots: sm2.NewCertPool(), Intermediates: sm2.NewCertPool()}

	// Load TLS root and intermediate CA identities
	gmmsp.tlsRootCerts = make([][]byte, len(conf.TlsRootCerts))
	rootCerts := make([]*sm2.Certificate, len(conf.TlsRootCerts))
	for i, trustedCert := range conf.TlsRootCerts {
		cert, err := gmmsp.getCertFromPem(trustedCert)
		if err != nil {
			return err
		}

		rootCerts[i] = cert
		gmmsp.tlsRootCerts[i] = trustedCert
		opts.Roots.AddCert(cert)
	}

	// make and fill the set of intermediate certs (if present)
	gmmsp.tlsIntermediateCerts = make([][]byte, len(conf.TlsIntermediateCerts))
	intermediateCerts := make([]*sm2.Certificate, len(conf.TlsIntermediateCerts))
	for i, trustedCert := range conf.TlsIntermediateCerts {
		cert, err := gmmsp.getCertFromPem(trustedCert)
		if err != nil {
			return err
		}

		intermediateCerts[i] = cert
		gmmsp.tlsIntermediateCerts[i] = trustedCert
		opts.Intermediates.AddCert(cert)
	}

	// ensure that our CAs are properly formed and that they are valid
	for _, cert := range append(append([]*sm2.Certificate{}, rootCerts...), intermediateCerts...) {
		if cert == nil {
			continue
		}

		if !cert.IsCA {
			return errors.Errorf("CA Certificate did not have the CA attribute, (SN: %x)", cert.SerialNumber)
		}
		if _, err := getSubjectKeyIdentifierFromCert(cert); err != nil {
			return errors.WithMessagef(err, "CA Certificate problem with Subject Key Identifier extension, (SN: %x)", cert.SerialNumber)
		}

		if err := gmmsp.validateTLSCAIdentity(cert, opts); err != nil {
			return errors.WithMessagef(err, "CA Certificate is not valid, (SN: %s)", cert.SerialNumber)
		}
	}

	return nil
}

func (gmmsp *gmmsp) setupV1(conf1 *m.FabricMSPConfig) error {
	err := gmmsp.preSetupV1(conf1)
	if err != nil {
		return err
	}

	err = gmmsp.postSetupV1(conf1)
	if err != nil {
		return err
	}

	return nil
}

func (gmmsp *gmmsp) preSetupV1(conf *m.FabricMSPConfig) error {
	// setup crypto config
	if err := gmmsp.setupCrypto(conf); err != nil {
		return err
	}

	// Setup CAs
	if err := gmmsp.setupCAs(conf); err != nil {
		return err
	}

	// Setup Admins
	if err := gmmsp.setupAdmins(conf); err != nil {
		return err
	}

	// Setup CRLs
	if err := gmmsp.setupCRLs(conf); err != nil {
		return err
	}

	// Finalize setup of the CAs
	if err := gmmsp.finalizeSetupCAs(); err != nil {
		return err
	}

	// setup the signer (if present)
	if err := gmmsp.setupSigningIdentity(conf); err != nil {
		return err
	}

	// setup TLS CAs
	if err := gmmsp.setupTLSCAs(conf); err != nil {
		return err
	}

	// setup the OUs
	if err := gmmsp.setupOUs(conf); err != nil {
		return err
	}

	return nil
}

func (gmmsp *gmmsp) preSetupV142(conf *m.FabricMSPConfig) error {
	// setup crypto config
	if err := gmmsp.setupCrypto(conf); err != nil {
		return err
	}

	/*	mspLogger.Infof("FabricMAPConfig---,%v", conf.Name)
		mspLogger.Infof("FabricMAPConfig---,%v", conf.RootCerts)
		mspLogger.Infof("FabricMAPConfig---,%v", conf.IntermediateCerts)*/
	// Setup CAs
	if err := gmmsp.setupCAs(conf); err != nil {
		return err
	}

	// Setup CRLs
	if err := gmmsp.setupCRLs(conf); err != nil {
		return err
	}

	// Finalize setup of the CAs
	if err := gmmsp.finalizeSetupCAs(); err != nil {
		return err
	}

	// setup the signer (if present)
	if err := gmmsp.setupSigningIdentity(conf); err != nil {
		return err
	}

	// setup TLS CAs
	if err := gmmsp.setupTLSCAs(conf); err != nil {
		return err
	}

	// setup the OUs
	if err := gmmsp.setupOUs(conf); err != nil {
		return err
	}

	// setup NodeOUs
	if err := gmmsp.setupNodeOUsV142(conf); err != nil {
		return err
	}

	// Setup Admins
	if err := gmmsp.setupAdmins(conf); err != nil {
		return err
	}

	return nil
}

func (gmmsp *gmmsp) postSetupV1(conf *m.FabricMSPConfig) error {
	// make sure that admins are valid members as well
	// this way, when we validate an admin MSP principal
	// we can simply check for exact match of certs
	for i, admin := range gmmsp.admins {
		err := admin.Validate()
		if err != nil {
			return errors.WithMessagef(err, "admin %d is invalid", i)
		}
	}

	return nil
}

func (gmmsp *gmmsp) setupV11(conf *m.FabricMSPConfig) error {
	err := gmmsp.preSetupV1(conf)
	if err != nil {
		return err
	}

	// setup NodeOUs
	if err := gmmsp.setupNodeOUs(conf); err != nil {
		return err
	}

	err = gmmsp.postSetupV11(conf)
	if err != nil {
		return err
	}

	return nil
}

func (gmmsp *gmmsp) setupV142(conf *m.FabricMSPConfig) error {
	err := gmmsp.preSetupV142(conf)
	if err != nil {
		return err
	}

	err = gmmsp.postSetupV142(conf)
	if err != nil {
		return err
	}

	return nil
}

func (gmmsp *gmmsp) postSetupV11(conf *m.FabricMSPConfig) error {
	// Check for OU enforcement
	if !gmmsp.ouEnforcement {
		// No enforcement required. Call post setup as per V1
		return gmmsp.postSetupV1(conf)
	}

	// Check that admins are clients
	principalBytes, err := proto.Marshal(&m.MSPRole{Role: m.MSPRole_CLIENT, MspIdentifier: gmmsp.name})
	if err != nil {
		return errors.Wrapf(err, "failed creating MSPRole_CLIENT")
	}
	principal := &m.MSPPrincipal{
		PrincipalClassification: m.MSPPrincipal_ROLE,
		Principal:               principalBytes}
	for i, admin := range gmmsp.admins {
		err = admin.SatisfiesPrincipal(principal)
		if err != nil {
			return errors.WithMessagef(err, "admin %d is invalid", i)
		}
	}

	return nil
}

func (gmmsp *gmmsp) postSetupV142(conf *m.FabricMSPConfig) error {
	// Check for OU enforcement
	if !gmmsp.ouEnforcement {
		// No enforcement required. Call post setup as per V1
		return gmmsp.postSetupV1(conf)
	}

	// Check that admins are clients or admins
	for i, admin := range gmmsp.admins {
		err1 := gmmsp.hasOURole(admin, m.MSPRole_CLIENT)
		err2 := gmmsp.hasOURole(admin, m.MSPRole_ADMIN)
		if err1 != nil && err2 != nil {
			return errors.Errorf("admin %d is invalid [%s,%s]", i, err1, err2)
		}
	}

	return nil
}
