/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/msp/idemix"
	"github.com/pkg/errors"
)

const (
	// GuomiBasedFactoryName is the name of the factory of the software-based BCCSP implementation
	IDEMIXFactoryName = "IDEMIX"
)

// SWFactory is the factory of the software-based BCCSP.
type IDEMIXFactory struct{}

// Name returns the name of this factory
func (f *IDEMIXFactory) Name() string {
	return IDEMIXFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *IDEMIXFactory) Get(bccsp bccsp.BCCSP) (msp.MSP, error) {
	return New3(msp.Options[msp.ProviderTypeToString(msp.IDEMIX)], bccsp)
}

// New create a new MSP instance depending on the passed Opts
func New3(opts msp.NewOpts, cryptoProvider bccsp.BCCSP) (msp.MSP, error) {
	switch opts.(type) {
	case *msp.IdemixNewOpts:
		switch opts.GetVersion() {
		case msp.MSPv1_0:
			return idemix.NewIdemixMsp(msp.MSPv1_0)
		case msp.MSPv1_1:
			return idemix.NewIdemixMsp(msp.MSPv1_0)
		case msp.MSPv1_3:
			return idemix.NewIdemixMsp(msp.MSPv1_0)
		case msp.MSPv1_4_3:
			return idemix.NewIdemixMsp(msp.MSPv1_0)
		default:
			return nil, errors.Errorf("Invalid *IdemixNewOpts. Version not recognized [%v]", opts.GetVersion())
		}
	default:
		return nil, errors.Errorf("Invalid msp.NewOpts instance. It must be either *BCCSPNewOpts or *IdemixNewOpts. It was [%v]", opts)
	}
}
