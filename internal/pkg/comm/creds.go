/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmtls"
	"github.com/tjfoc/gmtls/gmcredentials"
	"net"
	"sync"
	"time"

	"github.com/hyperledger/fabric/common/flogging"
	"google.golang.org/grpc/credentials"
)

var (
	ErrClientHandshakeNotImplemented = errors.New("core/comm: client handshakes are not implemented with serverCreds")
	ErrServerHandshakeNotImplemented = errors.New("core/comm: server handshakes are not implemented with clientCreds")
	ErrOverrideHostnameNotSupported  = errors.New("core/comm: OverrideServerName is not supported")

	// alpnProtoStr are the specified application level protocols for gRPC.
	alpnProtoStr = []string{"h2"}

	// Logger for TLS client connections
	tlsClientLogger = flogging.MustGetLogger("comm.tls")
)

// NewServerTransportCredentials returns a new initialized
// grpc/credentials.TransportCredentials
func NewServerTransportCredentials(
	serverConfig interface{},
	logger *flogging.FabricLogger) credentials.TransportCredentials {
	// NOTE: unlike the default grpc/credentials implementation, we do not
	// clone the tls.Config which allows us to update it dynamically
	if logger == nil {
		logger = tlsClientLogger
	}
	switch serverConfig.(type) {
	case *TLSConfig:
		serverConfig := serverConfig.(*TLSConfig)
		serverConfig.config.NextProtos = alpnProtoStr
		serverConfig.config.MinVersion = tls.VersionTLS12
		return &serverCreds{
			serverConfig: serverConfig,
			logger:       logger}
	case *TLSConfigGM:
		serverConfig := serverConfig.(*TLSConfigGM)
		serverConfig.config.NextProtos = alpnProtoStr
		serverConfig.config.MinVersion = tls.VersionTLS12
		return &serverCredsGM{
			serverConfig: serverConfig,
			logger:       logger}
	default:
		panic("Unsupport TLSConfig Type")
	}

}

// serverCreds is an implementation of grpc/credentials.TransportCredentials.
type serverCreds struct {
	serverConfig *TLSConfig
	logger       *flogging.FabricLogger
}

type serverCredsGM struct {
	serverConfig *TLSConfigGM
	logger       *flogging.FabricLogger
}

type TLSConfig struct {
	config *tls.Config
	lock   sync.RWMutex
}

type TLSConfigGM struct {
	config *gmtls.Config
	lock   sync.RWMutex
}

func NewTLSConfig(config *tls.Config) *TLSConfig {
	return &TLSConfig{
		config: config,
	}
}

func NewTLSConfigGM(config *gmtls.Config) *TLSConfigGM {
	return &TLSConfigGM{
		config: config,
	}
}

func (t *TLSConfig) Config() tls.Config {
	t.lock.RLock()
	defer t.lock.RUnlock()

	if t.config != nil {
		return *t.config.Clone()
	}

	return tls.Config{}
}
func (t *TLSConfigGM) Config() gmtls.Config {
	t.lock.RLock()
	defer t.lock.RUnlock()

	if t.config != nil {
		return *t.config.Clone()
	}

	return gmtls.Config{}
}

func (t *TLSConfig) AddClientRootCA(cert *x509.Certificate) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.config.ClientCAs.AddCert(cert)
}

func (t *TLSConfigGM) AddClientRootCA(cert *sm2.Certificate) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.config.ClientCAs.AddCert(cert)
}

func (t *TLSConfig) SetClientCAs(certPool *x509.CertPool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.config.ClientCAs = certPool
}

func (t *TLSConfigGM) SetClientCAs(certPool *sm2.CertPool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.config.ClientCAs = certPool
}

// ClientHandShake is not implemented for `serverCreds`.
func (sc *serverCreds) ClientHandshake(context.Context,
	string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, ErrClientHandshakeNotImplemented
}

func (sc *serverCredsGM) ClientHandshake(context.Context,
	string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, ErrClientHandshakeNotImplemented
}

// ServerHandshake does the authentication handshake for servers.
func (sc *serverCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	serverConfig := sc.serverConfig.Config()

	conn := tls.Server(rawConn, &serverConfig)
	l := sc.logger.With("remote address", conn.RemoteAddr().String())
	start := time.Now()
	if err := conn.Handshake(); err != nil {
		l.Errorf("Server TLS handshake failed in %s with error %s", time.Since(start), err)
		return nil, nil, err
	}
	l.Debugf("Server TLS handshake completed in %s", time.Since(start))
	return conn, credentials.TLSInfo{State: conn.ConnectionState()}, nil
}

func (sc *serverCredsGM) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	serverConfig := sc.serverConfig.Config()

	conn := gmtls.Server(rawConn, &serverConfig)
	l := sc.logger.With("remote address", conn.RemoteAddr().String())
	start := time.Now()
	if err := conn.Handshake(); err != nil {
		l.Errorf("Server GM TLS handshake failed in %s with error %s", time.Since(start), err)
		return nil, nil, err
	}
	l.Debugf("Server GM TLS handshake completed in %s", time.Since(start))
	return conn, gmcredentials.TLSInfo{State: conn.ConnectionState()}, nil}

// Info provides the ProtocolInfo of this TransportCredentials.
func (sc *serverCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  "1.2",
	}
}

// Info provides the ProtocolInfo of this TransportCredentials.
func (sc *serverCredsGM) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  "1.2",
	}
}

// Clone makes a copy of this TransportCredentials.
func (sc *serverCreds) Clone() credentials.TransportCredentials {
	config := sc.serverConfig.Config()
	serverConfig := NewTLSConfig(&config)
	return NewServerTransportCredentials(serverConfig, sc.logger)
}

// Clone makes a copy of this TransportCredentials.
func (sc *serverCredsGM) Clone() credentials.TransportCredentials {
	config := sc.serverConfig.Config()
	serverConfig := NewTLSConfigGM(&config)
	return NewServerTransportCredentials(serverConfig, sc.logger)
}

// OverrideServerName overrides the server name used to verify the hostname
// on the returned certificates from the server.
func (sc *serverCreds) OverrideServerName(string) error {
	return ErrOverrideHostnameNotSupported
}

func (sc *serverCredsGM) OverrideServerName(string) error {
	return ErrOverrideHostnameNotSupported
}

type DynamicClientCredentials struct {
	TLSConfig  *tls.Config
	TLSOptions []TLSOption
}

type DynamicGMClientCredentials struct {
	TLSConfig  *gmtls.Config
	TLSOptions []TLSGMOption
}

func (dtc *DynamicClientCredentials) latestConfig() *tls.Config {
	tlsConfigCopy := dtc.TLSConfig.Clone()
	for _, tlsOption := range dtc.TLSOptions {
		tlsOption(tlsConfigCopy)
	}
	return tlsConfigCopy
}

func (dtc *DynamicClientCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	l := tlsClientLogger.With("remote address", rawConn.RemoteAddr().String())
	creds := credentials.NewTLS(dtc.latestConfig())
	start := time.Now()
	conn, auth, err := creds.ClientHandshake(ctx, authority, rawConn)
	if err != nil {
		l.Errorf("Client TLS handshake failed after %s with error: %s", time.Since(start), err)
	} else {
		l.Debugf("Client TLS handshake completed in %s", time.Since(start))
	}
	return conn, auth, err
}

func (dtc *DynamicClientCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, ErrServerHandshakeNotImplemented
}

func (dtc *DynamicClientCredentials) Info() credentials.ProtocolInfo {
	return credentials.NewTLS(dtc.latestConfig()).Info()
}

func (dtc *DynamicClientCredentials) Clone() credentials.TransportCredentials {
	return credentials.NewTLS(dtc.latestConfig())
}

func (dtc *DynamicClientCredentials) OverrideServerName(name string) error {
	dtc.TLSConfig.ServerName = name
	return nil
}

func (dtc *DynamicGMClientCredentials) latestConfig() *gmtls.Config {
	tlsConfigCopy := dtc.TLSConfig.Clone()
	for _, tlsOption := range dtc.TLSOptions {
		tlsOption(tlsConfigCopy)
	}
	return tlsConfigCopy
}

func (dtc *DynamicGMClientCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	l := tlsClientLogger.With("remote address", rawConn.RemoteAddr().String())
	creds := gmcredentials.NewTLS(dtc.latestConfig())
	start := time.Now()
	conn, auth, err := creds.ClientHandshake(ctx, authority, rawConn)
	if err != nil {
		l.Errorf("Client GM TLS handshake failed after %s with error: %s", time.Since(start), err)
	} else {
		l.Debugf("Client TLS handshake completed in %s", time.Since(start))
	}
	return conn, auth, err
}

func (dtc *DynamicGMClientCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, ErrServerHandshakeNotImplemented
}

func (dtc *DynamicGMClientCredentials) Info() credentials.ProtocolInfo {
	return gmcredentials.NewTLS(dtc.latestConfig()).Info()
}

func (dtc *DynamicGMClientCredentials) Clone() credentials.TransportCredentials {
	return gmcredentials.NewTLS(dtc.latestConfig())
}

func (dtc *DynamicGMClientCredentials) OverrideServerName(name string) error {
	dtc.TLSConfig.ServerName = name
	return nil
}
