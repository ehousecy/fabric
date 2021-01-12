/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"github.com/hyperledger/fabric/msp"
	sw2 "github.com/hyperledger/fabric/msp/sw"
	"reflect"
	"runtime"
	"testing"

	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/stretchr/testify/assert"
)

func TestNewInvalidOpts(t *testing.T) {
	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	assert.NoError(t, err)

	i, err := New(nil, cryptoProvider)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid msp.NewOpts instance. It must be either *BCCSPNewOpts or *IdemixNewOpts. It was [<nil>]")
	assert.Nil(t, i)

	i, err = New(&msp.BCCSPNewOpts{NewBaseOpts: msp.NewBaseOpts{Version: -1}}, cryptoProvider)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid *BCCSPNewOpts. Version not recognized [-1]")
	assert.Nil(t, i)

	i, err = New(&msp.IdemixNewOpts{NewBaseOpts: msp.NewBaseOpts{Version: -1}}, cryptoProvider)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid *IdemixNewOpts. Version not recognized [-1]")
	assert.Nil(t, i)
}

func TestNew(t *testing.T) {
	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	assert.NoError(t, err)

	i, err := New(&BCCSPNewOpts{NewBaseOpts{Version: MSPv1_0}}, cryptoProvider)
	assert.NoError(t, err)
	assert.NotNil(t, i)
	assert.Equal(t, MSPVersion(MSPv1_0), i.(*sw2.bccspmsp).version)
	assert.Equal(t,
		runtime.FuncForPC(reflect.ValueOf(i.(*sw2.bccspmsp).internalSetupFunc).Pointer()).Name(),
		runtime.FuncForPC(reflect.ValueOf(i.(*sw2.bccspmsp).setupV1).Pointer()).Name(),
	)
	assert.Equal(t,
		runtime.FuncForPC(reflect.ValueOf(i.(*sw2.bccspmsp).internalValidateIdentityOusFunc).Pointer()).Name(),
		runtime.FuncForPC(reflect.ValueOf(i.(*sw2.bccspmsp).validateIdentityOUsV1).Pointer()).Name(),
	)

	i, err = New(&BCCSPNewOpts{NewBaseOpts{Version: MSPv1_1}}, cryptoProvider)
	assert.NoError(t, err)
	assert.NotNil(t, i)
	assert.Equal(t, MSPVersion(MSPv1_1), i.(*sw2.bccspmsp).version)
	assert.Equal(t,
		runtime.FuncForPC(reflect.ValueOf(i.(*sw2.bccspmsp).internalSetupFunc).Pointer()).Name(),
		runtime.FuncForPC(reflect.ValueOf(i.(*sw2.bccspmsp).setupV11).Pointer()).Name(),
	)
	assert.Equal(t,
		runtime.FuncForPC(reflect.ValueOf(i.(*sw2.bccspmsp).internalValidateIdentityOusFunc).Pointer()).Name(),
		runtime.FuncForPC(reflect.ValueOf(i.(*sw2.bccspmsp).validateIdentityOUsV11).Pointer()).Name(),
	)

	i, err = New(&IdemixNewOpts{NewBaseOpts{Version: MSPv1_0}}, cryptoProvider)
	assert.Error(t, err)
	assert.Nil(t, i)
	assert.Contains(t, err.Error(), "Invalid *IdemixNewOpts. Version not recognized [0]")

	i, err = New(&IdemixNewOpts{NewBaseOpts{Version: MSPv1_1}}, cryptoProvider)
	assert.NoError(t, err)
	assert.NotNil(t, i)
}
