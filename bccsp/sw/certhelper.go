/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sw

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	gmtls "github.com/Hyperledger-TWGC/ccs-gm/tls"
	x509GM "github.com/Hyperledger-TWGC/ccs-gm/x509"
	"io"
	"io/ioutil"
	"math/big"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
)

// //调用SM2接口生成SM2证书
// func CreateCertificateToMem(template, parent *x509.Certificate,key bccsp.Key) (cert []byte,err error) {
// 	pk := key.(*gmsm2PrivateKey).privKey
// 	bigint := getRandBigInt()
// 	if(template.SerialNumber == nil){
// 		template.SerialNumber = bigint
// 	}
// 	if parent.SerialNumber == nil{
// 		parent.SerialNumber = bigint
// 	}

// 	sm2Temcert := ParseX509Certificate2Sm2(template)
// 	sm2Parcert := ParseX509Certificate2Sm2(parent)
// 	switch template.PublicKey.(type){
// 	case sm2.PublicKey:
// 		cert, err = sm2.CreateCertificateToMem(sm2Temcert,sm2Parcert, template.PublicKey.(*sm2.PublicKey),pk)
// 		return
// 	default:
// 		return nil ,fmt.Errorf("gm certhelper not sm2.PublicKey")
// 	}
// }

// //调用SM2接口生成SM2证书请求
// func CreateCertificateRequestToMem(certificateRequest *x509.CertificateRequest,key bccsp.Key) (csr []byte,err error) {
// 	pk := key.(*gmsm2PrivateKey).privKey
// 	sm2Req := ParseX509CertificateRequest2Sm2(certificateRequest)
// 	csr,err = sm2.CreateCertificateRequestToMem(sm2Req,pk)
// 	return
// }

func createCertificateToPem(template, parent *x509GM.Certificate, pub, priv interface{}) ([]byte, error) {
	der, err := x509GM.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

//调用SM2接口生成SM2证书
func CreateCertificateToMem(template, parent *x509GM.Certificate, signer crypto.Signer) (cert []byte, err error) {
	switch template.PublicKey.(type) {
	case *sm2.PublicKey:
		pub := template.PublicKey.(*sm2.PublicKey)
		var puk = sm2.PublicKey{
			Curve: sm2.P256(),
			X:     pub.X,
			Y:     pub.Y,
		}
		cert, err = createCertificateToPem(template, parent, &puk, signer)
	case *ecdsa.PublicKey:
		pub := template.PublicKey.(*ecdsa.PublicKey)
		var puk = sm2.PublicKey{
			Curve: sm2.P256(),
			X:     pub.X,
			Y:     pub.Y,
		}
		cert, err = createCertificateToPem(template, parent, &puk, signer)
	}
	return
}
func createCertificateRequestToMem(certificateRequest *x509GM.CertificateRequest, priv interface{}) ([]byte, error) {
	der, err := x509GM.CreateCertificateRequest(rand.Reader, certificateRequest, priv)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

//调用SM2接口生成SM2证书请求
func CreateSm2CertificateRequestToMem(certificateRequest *x509GM.CertificateRequest, signer crypto.Signer) (csr []byte, err error) {
	csr, err = createCertificateRequestToMem(certificateRequest, signer)
	return
}

// X509 证书请求转换 SM2证书请求
func ParseX509CertificateRequest2Sm2(x509req *x509.CertificateRequest) *x509GM.CertificateRequest {
	sm2req := &x509GM.CertificateRequest{
		Raw:                      x509req.Raw,                      // Complete ASN.1 DER content (CSR, signature algorithm and signature).
		RawTBSCertificateRequest: x509req.RawTBSCertificateRequest, // Certificate request info part of raw ASN.1 DER content.
		RawSubjectPublicKeyInfo:  x509req.RawSubjectPublicKeyInfo,  // DER encoded SubjectPublicKeyInfo.
		RawSubject:               x509req.RawSubject,               // DER encoded Subject.

		Version:            x509req.Version,
		Signature:          x509req.Signature,
		SignatureAlgorithm: x509GM.SignatureAlgorithm(x509req.SignatureAlgorithm),

		PublicKeyAlgorithm: x509GM.PublicKeyAlgorithm(x509req.PublicKeyAlgorithm),
		PublicKey:          x509req.PublicKey,

		Subject: x509req.Subject,

		// Attributes is the dried husk of a bug and shouldn't be used.
		Attributes: x509req.Attributes,

		// Extensions contains raw X.509 extensions. When parsing CSRs, this
		// can be used to extract extensions that are not parsed by this
		// package.
		Extensions: x509req.Extensions,

		// ExtraExtensions contains extensions to be copied, raw, into any
		// marshaled CSR. Values override any extensions that would otherwise
		// be produced based on the other fields but are overridden by any
		// extensions specified in Attributes.
		//
		// The ExtraExtensions field is not populated when parsing CSRs, see
		// Extensions.
		ExtraExtensions: x509req.ExtraExtensions,

		// Subject Alternate Name values.
		DNSNames:       x509req.DNSNames,
		EmailAddresses: x509req.EmailAddresses,
		IPAddresses:    x509req.IPAddresses,
	}
	return sm2req
}

// X509 证书请求转换 SM2证书请求
func ParseSM2CertificateRequest2X509(x509req *x509GM.CertificateRequest) *x509.CertificateRequest {
	sm2req := &x509.CertificateRequest{
		Raw:                      x509req.Raw,                      // Complete ASN.1 DER content (CSR, signature algorithm and signature).
		RawTBSCertificateRequest: x509req.RawTBSCertificateRequest, // Certificate request info part of raw ASN.1 DER content.
		RawSubjectPublicKeyInfo:  x509req.RawSubjectPublicKeyInfo,  // DER encoded SubjectPublicKeyInfo.
		RawSubject:               x509req.RawSubject,               // DER encoded Subject.

		Version:            x509req.Version,
		Signature:          x509req.Signature,
		SignatureAlgorithm: x509.SignatureAlgorithm(x509req.SignatureAlgorithm),

		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(x509req.PublicKeyAlgorithm),
		PublicKey:          x509req.PublicKey,

		Subject: x509req.Subject,

		// Attributes is the dried husk of a bug and shouldn't be used.
		Attributes: x509req.Attributes,

		// Extensions contains raw X.509 extensions. When parsing CSRs, this
		// can be used to extract extensions that are not parsed by this
		// package.
		Extensions: x509req.Extensions,

		// ExtraExtensions contains extensions to be copied, raw, into any
		// marshaled CSR. Values override any extensions that would otherwise
		// be produced based on the other fields but are overridden by any
		// extensions specified in Attributes.
		//
		// The ExtraExtensions field is not populated when parsing CSRs, see
		// Extensions.
		ExtraExtensions: x509req.ExtraExtensions,

		// Subject Alternate Name values.
		DNSNames:       x509req.DNSNames,
		EmailAddresses: x509req.EmailAddresses,
		IPAddresses:    x509req.IPAddresses,
	}
	return sm2req
}

// X509证书格式转换为 SM2证书格式
func ParseX509Certificate2Sm2(x509Cert *x509.Certificate) *x509GM.Certificate {
	sm2cert := &x509GM.Certificate{
		Raw:                     x509Cert.Raw,
		RawTBSCertificate:       x509Cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo: x509Cert.RawSubjectPublicKeyInfo,
		RawSubject:              x509Cert.RawSubject,
		RawIssuer:               x509Cert.RawIssuer,

		Signature:          x509Cert.Signature,
		SignatureAlgorithm: x509GM.SignatureAlgorithm(x509Cert.SignatureAlgorithm),

		PublicKeyAlgorithm: x509GM.PublicKeyAlgorithm(x509Cert.PublicKeyAlgorithm),
		PublicKey:          x509Cert.PublicKey,

		Version:      x509Cert.Version,
		SerialNumber: x509Cert.SerialNumber,
		Issuer:       x509Cert.Issuer,
		Subject:      x509Cert.Subject,
		NotBefore:    x509Cert.NotBefore,
		NotAfter:     x509Cert.NotAfter,
		KeyUsage:     x509GM.KeyUsage(x509Cert.KeyUsage),

		Extensions: x509Cert.Extensions,

		ExtraExtensions: x509Cert.ExtraExtensions,

		UnhandledCriticalExtensions: x509Cert.UnhandledCriticalExtensions,

		//ExtKeyUsage:	[]x509.ExtKeyUsage(x509Cert.ExtKeyUsage) ,
		UnknownExtKeyUsage: x509Cert.UnknownExtKeyUsage,

		BasicConstraintsValid: x509Cert.BasicConstraintsValid,
		IsCA:                  x509Cert.IsCA,
		MaxPathLen:            x509Cert.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero: x509Cert.MaxPathLenZero,

		SubjectKeyId:   x509Cert.SubjectKeyId,
		AuthorityKeyId: x509Cert.AuthorityKeyId,

		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:            x509Cert.OCSPServer,
		IssuingCertificateURL: x509Cert.IssuingCertificateURL,

		// Subject Alternate Name values
		DNSNames:       x509Cert.DNSNames,
		EmailAddresses: x509Cert.EmailAddresses,
		IPAddresses:    x509Cert.IPAddresses,

		// Name constraints
		PermittedDNSDomainsCritical: x509Cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         x509Cert.PermittedDNSDomains,

		// CRL Distribution Points
		CRLDistributionPoints: x509Cert.CRLDistributionPoints,

		PolicyIdentifiers: x509Cert.PolicyIdentifiers,
	}
	for _, val := range x509Cert.ExtKeyUsage {
		sm2cert.ExtKeyUsage = append(sm2cert.ExtKeyUsage, x509GM.ExtKeyUsage(val))
	}

	return sm2cert
}

// X509证书格式转换为 SM2证书格式
func ParseSm2CertificateRequest2X509(x509Cert *x509GM.Certificate) *x509.Certificate {
	sm2cert := &x509.Certificate{
		Raw:                     x509Cert.Raw,
		RawTBSCertificate:       x509Cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo: x509Cert.RawSubjectPublicKeyInfo,
		RawSubject:              x509Cert.RawSubject,
		RawIssuer:               x509Cert.RawIssuer,

		Signature:          x509Cert.Signature,
		SignatureAlgorithm: x509.SignatureAlgorithm(x509Cert.SignatureAlgorithm),

		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(x509Cert.PublicKeyAlgorithm),
		PublicKey:          x509Cert.PublicKey,

		Version:      x509Cert.Version,
		SerialNumber: x509Cert.SerialNumber,
		Issuer:       x509Cert.Issuer,
		Subject:      x509Cert.Subject,
		NotBefore:    x509Cert.NotBefore,
		NotAfter:     x509Cert.NotAfter,
		KeyUsage:     x509.KeyUsage(x509Cert.KeyUsage),

		Extensions: x509Cert.Extensions,

		ExtraExtensions: x509Cert.ExtraExtensions,

		UnhandledCriticalExtensions: x509Cert.UnhandledCriticalExtensions,

		//ExtKeyUsage:	[]x509.ExtKeyUsage(x509Cert.ExtKeyUsage) ,
		UnknownExtKeyUsage: x509Cert.UnknownExtKeyUsage,

		BasicConstraintsValid: x509Cert.BasicConstraintsValid,
		IsCA:                  x509Cert.IsCA,
		MaxPathLen:            x509Cert.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero: x509Cert.MaxPathLenZero,

		SubjectKeyId:   x509Cert.SubjectKeyId,
		AuthorityKeyId: x509Cert.AuthorityKeyId,

		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:            x509Cert.OCSPServer,
		IssuingCertificateURL: x509Cert.IssuingCertificateURL,

		// Subject Alternate Name values
		DNSNames:       x509Cert.DNSNames,
		EmailAddresses: x509Cert.EmailAddresses,
		IPAddresses:    x509Cert.IPAddresses,

		// Name constraints
		PermittedDNSDomainsCritical: x509Cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         x509Cert.PermittedDNSDomains,

		// CRL Distribution Points
		CRLDistributionPoints: x509Cert.CRLDistributionPoints,

		PolicyIdentifiers: x509Cert.PolicyIdentifiers,
	}
	for _, val := range x509Cert.ExtKeyUsage {
		sm2cert.ExtKeyUsage = append(sm2cert.ExtKeyUsage, x509.ExtKeyUsage(val))
	}

	return sm2cert
}

func ParseGMTLSCertificate2TlsCertificate(certificate gmtls.Certificate) *tls.Certificate {
	cert := &tls.Certificate{
		Certificate: certificate.Certificate,
		PrivateKey:  certificate.PrivateKey,
		Leaf:        ParseSm2Certificate2X509(certificate.Leaf),
	}
	return cert
}

//sm2 证书转换 x509 证书
func ParseSm2Certificate2X509(sm2Cert *x509GM.Certificate) *x509.Certificate {
	if sm2Cert == nil {
		return nil
	}
	x509cert := &x509.Certificate{
		Raw:                     sm2Cert.Raw,
		RawTBSCertificate:       sm2Cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo: sm2Cert.RawSubjectPublicKeyInfo,
		RawSubject:              sm2Cert.RawSubject,
		RawIssuer:               sm2Cert.RawIssuer,

		Signature:          sm2Cert.Signature,
		SignatureAlgorithm: x509.SignatureAlgorithm(sm2Cert.SignatureAlgorithm),

		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(sm2Cert.PublicKeyAlgorithm),
		PublicKey:          sm2Cert.PublicKey,

		Version:      sm2Cert.Version,
		SerialNumber: sm2Cert.SerialNumber,
		Issuer:       sm2Cert.Issuer,
		Subject:      sm2Cert.Subject,
		NotBefore:    sm2Cert.NotBefore,
		NotAfter:     sm2Cert.NotAfter,
		KeyUsage:     x509.KeyUsage(sm2Cert.KeyUsage),

		Extensions: sm2Cert.Extensions,

		ExtraExtensions: sm2Cert.ExtraExtensions,

		UnhandledCriticalExtensions: sm2Cert.UnhandledCriticalExtensions,

		//ExtKeyUsage:	[]x509.ExtKeyUsage(sm2Cert.ExtKeyUsage) ,
		UnknownExtKeyUsage: sm2Cert.UnknownExtKeyUsage,

		BasicConstraintsValid: sm2Cert.BasicConstraintsValid,
		IsCA:                  sm2Cert.IsCA,
		MaxPathLen:            sm2Cert.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero: sm2Cert.MaxPathLenZero,

		SubjectKeyId:   sm2Cert.SubjectKeyId,
		AuthorityKeyId: sm2Cert.AuthorityKeyId,

		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:            sm2Cert.OCSPServer,
		IssuingCertificateURL: sm2Cert.IssuingCertificateURL,

		// Subject Alternate Name values
		DNSNames:       sm2Cert.DNSNames,
		EmailAddresses: sm2Cert.EmailAddresses,
		IPAddresses:    sm2Cert.IPAddresses,

		// Name constraints
		PermittedDNSDomainsCritical: sm2Cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         sm2Cert.PermittedDNSDomains,

		// CRL Distribution Points
		CRLDistributionPoints: sm2Cert.CRLDistributionPoints,

		PolicyIdentifiers: sm2Cert.PolicyIdentifiers,
	}
	for _, val := range sm2Cert.ExtKeyUsage {
		x509cert.ExtKeyUsage = append(x509cert.ExtKeyUsage, x509.ExtKeyUsage(val))
	}

	return x509cert
}

//随机生成序列号
func getRandBigInt() *big.Int {
	serialNumber := make([]byte, 20)
	_, err := io.ReadFull(rand.Reader, serialNumber)
	if err != nil {
		//return nil, cferr.Wrap(cferr.CertificateError, cferr.Unknown, err)
	}
	// SetBytes interprets buf as the bytes of a big-endian
	// unsigned integer. The leading byte should be masked
	// off to ensure it isn't negative.
	serialNumber[0] &= 0x7F
	//template.SerialNumber = new(big.Int).SetBytes(serialNumber)
	return new(big.Int).SetBytes(serialNumber)
}

func ReadCertificateRequestFromMem(data []byte) (*x509GM.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return x509GM.ParseCertificateRequest(block.Bytes)
}

func ReadCertificateRequestFromPem(FileName string) (*x509GM.CertificateRequest, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadCertificateRequestFromMem(data)
}

func ReadCertificateFromMem(data []byte) (*x509GM.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return x509GM.ParseCertificate(block.Bytes)
}

func ReadCertificateFromPem(FileName string) (*x509GM.Certificate, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadCertificateFromMem(data)
}

func ReadPrivateKeyFromPem(privateKeyPem []byte, pwd []byte) (*sm2.PrivateKey, error) {
	var block *pem.Block
	block, _ = pem.Decode(privateKeyPem)
	if block == nil {
		return nil, errors.New("failed to decode private key")
	}
	priv, err := x509GM.ParsePKCS8PrivateKey(block.Bytes)
	return priv.(*sm2.PrivateKey), err
}

func WritePrivateKeyToPem(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	var block *pem.Block
	der, err := x509GM.MarshalECPrivateKey(key) //Convert private key to DER format
	if err != nil {
		return nil, err
	}
	if pwd != nil {
		block = &pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: der,
		}
	} else {
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
	}
	certPem := pem.EncodeToMemory(block)
	return certPem, nil
}
