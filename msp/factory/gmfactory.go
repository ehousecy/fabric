/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/msp/gm"
	"github.com/pkg/errors"
)

const (
	// GuomiBasedFactoryName is the name of the factory of the software-based BCCSP implementation
	GuomiBasedFactoryName = "GM"
)

// SWFactory is the factory of the software-based BCCSP.
type GMFactory struct{}

// Name returns the name of this factory
func (f *GMFactory) Name() string {
	return GuomiBasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *GMFactory) Get(newOpts msp.NewOpts, bccsp bccsp.BCCSP) (msp.MSP, error) {
	return New2(newOpts, bccsp)
}

// New create a new MSP instance depending on the passed Opts
func New2(opts msp.NewOpts, cryptoProvider bccsp.BCCSP) (msp.MSP, error) {
		switch opts.GetVersion() {
		case msp.MSPv1_0:
			return gm.NewBccspMsp(msp.MSPv1_0, cryptoProvider)
		case msp.MSPv1_1:
			return gm.NewBccspMsp(msp.MSPv1_1, cryptoProvider)
		case msp.MSPv1_3:
			return gm.NewBccspMsp(msp.MSPv1_3, cryptoProvider)
		case msp.MSPv1_4_3:
			return gm.NewBccspMsp(msp.MSPv1_4_3, cryptoProvider)
		default:
			return nil, errors.Errorf("Invalid *BCCSPNewOpts. Version not recognized [%v]", opts.GetVersion())
		}
}
