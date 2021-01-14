/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/tjfoc/gmsm/sm2"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hyperledger/fabric/internal/cryptogen/csp"
	"github.com/pkg/errors"
)

type CA struct {
	Name               string
	Country            string
	Province           string
	Locality           string
	OrganizationalUnit string
	StreetAddress      string
	PostalCode         string
	Signer             crypto.Signer
	SignCert           interface{}
}

// NewCA creates an instance of CA and saves the signing key pair in
// baseDir/name
func NewCA(
	baseDir,
	org,
	name,
	country,
	province,
	locality,
	orgUnit,
	streetAddress,
	postalCode string,
	useGM bool,
) (*CA, error) {

	var ca *CA

	err := os.MkdirAll(baseDir, 0755)
	if err != nil {
		return nil, err
	}

	template := getTemplate(org,
		name,
		country,
		province,
		locality,
		orgUnit,
		streetAddress,
		postalCode, useGM)

	var x509Cert interface{}

	if useGM {
		template := template.(sm2.Certificate)
		template.KeyUsage |= sm2.KeyUsageDigitalSignature |
			sm2.KeyUsageKeyEncipherment | sm2.KeyUsageCertSign |
			sm2.KeyUsageCRLSign
		template.ExtKeyUsage = []sm2.ExtKeyUsage{
			sm2.ExtKeyUsageClientAuth,
			sm2.ExtKeyUsageServerAuth,
		}
		priv, err := csp.GenerateSM2PrivateKey(baseDir)
		if err != nil {
			return nil, err
		}
		template.SubjectKeyId = computeSKI(priv)
		template.SignatureAlgorithm = sm2.SM2WithSM3
		x509Cert, err = genCertificate(
			baseDir,
			name,
			&template,
			&template,
			&priv.PublicKey,
			priv,
		)
		if err != nil {
			return nil, err
		}
		ca = &CA{
			Name:               name,
			Signer:             priv,
			SignCert:           x509Cert,
			Country:            country,
			Province:           province,
			Locality:           locality,
			OrganizationalUnit: orgUnit,
			StreetAddress:      streetAddress,
			PostalCode:         postalCode,
		}

		return ca, err
	} else {
		template := template.(x509.Certificate)
		template.KeyUsage |= x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign
		template.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		}
		priv, err := csp.GeneratePrivateKey(baseDir)
		if err != nil {
			return nil, err
		}
		template.SubjectKeyId = computeSKI(priv)
		x509Cert, err = genCertificate(
			baseDir,
			name,
			&template,
			&template,
			&priv.PublicKey,
			priv,
		)
		if err != nil {
			return nil, err
		}
		ca = &CA{
			Name: name,
			Signer: &csp.ECDSASigner{
				PrivateKey: priv,
			},
			SignCert:           x509Cert,
			Country:            country,
			Province:           province,
			Locality:           locality,
			OrganizationalUnit: orgUnit,
			StreetAddress:      streetAddress,
			PostalCode:         postalCode,
		}

		return ca, err
	}
}

// SignCertificate creates a signed certificate based on a built-in template
// and saves it in baseDir/name
func (ca *CA) SignCertificate(
	baseDir,
	name string,
	orgUnits,
	alternateNames []string,
	pub *ecdsa.PublicKey,
	ku x509.KeyUsage,
	eku []x509.ExtKeyUsage,
) (interface{}, error) {

	template := x509Template()
	template.KeyUsage = ku
	template.ExtKeyUsage = eku

	//set the organization for the subject
	subject := subjectTemplateAdditional(
		ca.Country,
		ca.Province,
		ca.Locality,
		ca.OrganizationalUnit,
		ca.StreetAddress,
		ca.PostalCode,
	)
	subject.CommonName = name

	subject.OrganizationalUnit = append(subject.OrganizationalUnit, orgUnits...)

	template.Subject = subject
	for _, san := range alternateNames {
		// try to parse as an IP address first
		ip := net.ParseIP(san)
		if ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	cert, err := genCertificate(
		baseDir,
		name,
		&template,
		ca.SignCert,
		pub,
		ca.Signer,
	)

	if err != nil {
		return nil, err
	}

	return cert, nil
}

// SignCertificate creates a signed certificate based on a built-in template
// and saves it in baseDir/name
func (ca *CA) SignSM2Certificate(
	baseDir,
	name string,
	orgUnits,
	alternateNames []string,
	pub *sm2.PublicKey,
	ku sm2.KeyUsage,
	eku []sm2.ExtKeyUsage,
) (interface{}, error) {

	template := SM2Template()
	template.KeyUsage = ku
	template.ExtKeyUsage = eku
	template.SignatureAlgorithm = sm2.SM2WithSM3

	//set the organization for the subject
	subject := subjectTemplateAdditional(
		ca.Country,
		ca.Province,
		ca.Locality,
		ca.OrganizationalUnit,
		ca.StreetAddress,
		ca.PostalCode,
	)
	subject.CommonName = name

	subject.OrganizationalUnit = append(subject.OrganizationalUnit, orgUnits...)

	template.Subject = subject
	for _, san := range alternateNames {
		// try to parse as an IP address first
		ip := net.ParseIP(san)
		if ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	cert, err := genCertificate(
		baseDir,
		name,
		&template,
		ca.SignCert,
		pub,
		ca.Signer,
	)

	if err != nil {
		return nil, err
	}

	return cert, nil
}

// compute Subject Key Identifier
func computeSKI(privKey interface{}) []byte {
	switch privKey.(type) {
	case *ecdsa.PrivateKey:
		// Marshall the public key
		privKey := privKey.(*ecdsa.PrivateKey)
		raw := elliptic.Marshal(privKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)

		// Hash it
		hash := sha256.Sum256(raw)
		return hash[:]
	case *sm2.PrivateKey:
		//Marshall the public key
		privKey := privKey.(*sm2.PrivateKey)
		raw := elliptic.Marshal(privKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)
		// Hash it
		hash := sha256.New()
		hash.Write(raw)
		return hash.Sum(nil)
	default:
		panic("unSupport privateKey type")
	}

}

// default template for X509 subject
func subjectTemplate() pkix.Name {
	return pkix.Name{
		Country:  []string{"US"},
		Locality: []string{"San Francisco"},
		Province: []string{"California"},
	}
}

// Additional for X509 subject
func subjectTemplateAdditional(
	country,
	province,
	locality,
	orgUnit,
	streetAddress,
	postalCode string,
) pkix.Name {
	name := subjectTemplate()
	if len(country) >= 1 {
		name.Country = []string{country}
	}
	if len(province) >= 1 {
		name.Province = []string{province}
	}

	if len(locality) >= 1 {
		name.Locality = []string{locality}
	}
	if len(orgUnit) >= 1 {
		name.OrganizationalUnit = []string{orgUnit}
	}
	if len(streetAddress) >= 1 {
		name.StreetAddress = []string{streetAddress}
	}
	if len(postalCode) >= 1 {
		name.PostalCode = []string{postalCode}
	}
	return name
}

func getTemplate(org, name, country, province, locality, orgUnit, streetAddress, postalCode string, useGM bool) interface{} {
	if useGM {
		template := SM2Template()
		//this is a CA
		template.IsCA = true

		//set the organization for the subject
		subject := subjectTemplateAdditional(country, province, locality, orgUnit, streetAddress, postalCode)
		subject.Organization = []string{org}
		subject.CommonName = name

		template.Subject = subject
		return template
	} else {
		template := x509Template()
		//this is a CA
		template.IsCA = true

		//set the organization for the subject
		subject := subjectTemplateAdditional(country, province, locality, orgUnit, streetAddress, postalCode)
		subject.Organization = []string{org}
		subject.CommonName = name

		template.Subject = subject
		return template
	}
}

// default template for X509 certificates
func x509Template() x509.Certificate {

	// generate a serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	// set expiry to around 10 years
	expiry := 3650 * 24 * time.Hour
	// round minute and backdate 5 minutes
	notBefore := time.Now().Round(time.Minute).Add(-5 * time.Minute).UTC()

	//basic template to use
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(expiry).UTC(),
		BasicConstraintsValid: true,
	}
	return template

}

// default template for X509 certificates
func SM2Template() sm2.Certificate {

	// generate a serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	// set expiry to around 10 years
	expiry := 3650 * 24 * time.Hour
	// round minute and backdate 5 minutes
	notBefore := time.Now().Round(time.Minute).Add(-5 * time.Minute).UTC()

	//basic template to use
	template := sm2.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(expiry).UTC(),
		BasicConstraintsValid: true,
	}
	return template

}

func genCertificate(
	baseDir,
	name string,
	template,
	parent interface{},
	pub interface{},
	priv interface{},
) (interface{}, error) {
	switch parent.(type) {
	case *x509.Certificate:
		return genCertificateECDSA(baseDir, name, template.(*x509.Certificate), parent.(*x509.Certificate), pub.(*ecdsa.PublicKey), priv)
	case *sm2.Certificate:
		return genCertificateSM2(baseDir, name, template.(*sm2.Certificate), parent.(*sm2.Certificate), pub.(*sm2.PublicKey), priv)
	default:
		return nil, errors.Errorf("UnSupport certificate type : %s", parent)
	}
}

// generate a signed X509 certificate using ECDSA
func genCertificateECDSA(
	baseDir,
	name string,
	template,
	parent *x509.Certificate,
	pub *ecdsa.PublicKey,
	priv interface{},
) (*x509.Certificate, error) {

	//create the x509 public cert
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	//write cert out to file
	fileName := filepath.Join(baseDir, name+"-cert.pem")
	certFile, err := os.Create(fileName)
	if err != nil {
		return nil, err
	}
	//pem encode the cert
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certFile.Close()
	if err != nil {
		return nil, err
	}

	x509Cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil
}

// generate a signed X509 certificate using ECDSA
func genCertificateSM2(
	baseDir,
	name string,
	template,
	parent *sm2.Certificate,
	pub *sm2.PublicKey,
	priv interface{},
) (*sm2.Certificate, error) {

	//create the x509 public cert
	certBytes, err := sm2.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	//write cert out to file
	fileName := filepath.Join(baseDir, name+"-cert.pem")
	certFile, err := os.Create(fileName)
	if err != nil {
		return nil, err
	}
	//pem encode the cert
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certFile.Close()
	if err != nil {
		return nil, err
	}

	x509Cert, err := sm2.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil
}

// LoadCertificateECDSA load a ecdsa cert from a file in cert path
func LoadCertificateECDSA(certPath string) (*x509.Certificate, error) {
	var cert *x509.Certificate
	var err error

	walkFunc := func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".pem") {
			rawCert, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			block, _ := pem.Decode(rawCert)
			if block == nil || block.Type != "CERTIFICATE" {
				return errors.Errorf("%s: wrong PEM encoding", path)
			}
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return errors.Errorf("%s: wrong DER encoding", path)
			}
		}
		return nil
	}

	err = filepath.Walk(certPath, walkFunc)
	if err != nil {
		return nil, err
	}

	return cert, err
}
