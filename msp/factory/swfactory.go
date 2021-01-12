/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/msp/sw"
	"github.com/pkg/errors"
)

const (
	// SoftwareBasedFactoryName is the name of the factory of the software-based BCCSP implementation
	SoftwareBasedFactoryName = "SW"
)

// SWFactory is the factory of the software-based BCCSP.
type SWFactory struct{}

// Name returns the name of this factory
func (f *SWFactory) Name() string {
	return SoftwareBasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *SWFactory) Get(bccsp bccsp.BCCSP) (msp.MSP, error) {
	return New(msp.Options[msp.ProviderTypeToString(msp.FABRIC)], bccsp)
}

// New create a new MSP instance depending on the passed Opts
func New(opts msp.NewOpts, cryptoProvider bccsp.BCCSP) (msp.MSP, error) {
	switch opts.(type) {
	case *msp.BCCSPNewOpts:
		switch opts.GetVersion() {
		case msp.MSPv1_0:
			return sw.NewBccspMsp(msp.MSPv1_0, cryptoProvider)
		case msp.MSPv1_1:
			return sw.NewBccspMsp(msp.MSPv1_1, cryptoProvider)
		case msp.MSPv1_3:
			return sw.NewBccspMsp(msp.MSPv1_3, cryptoProvider)
		case msp.MSPv1_4_3:
			return sw.NewBccspMsp(msp.MSPv1_4_3, cryptoProvider)
		default:
			return nil, errors.Errorf("Invalid *BCCSPNewOpts. Version not recognized [%v]", opts.GetVersion())
		}
	default:
		return nil, errors.Errorf("Invalid msp.NewOpts instance. It must be either *BCCSPNewOpts or *IdemixNewOpts. It was [%v]", opts)
	}
}
