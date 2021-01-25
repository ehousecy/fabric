package factory

import (
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/gm"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric/msp"
	"github.com/pkg/errors"
)

type MSPFactory interface {

	// Name returns the name of this factory
	Name() string

	// Get returns an instance of MSP using opts.
	Get(newOpts msp.NewOpts, bccsp bccsp.BCCSP) (msp.MSP, error)
}

func GetDefault(newOpts msp.NewOpts, bccsp bccsp.BCCSP) (msp.MSP, error) {
	var msp1 msp.MSP
	var err error
	switch newOpts.(type) {
	case *msp.BCCSPNewOpts:
		switch bccsp.(type) {
		case *sw.CSP:
			msp1, err = (&SWFactory{}).Get(newOpts, bccsp)
		case *gm.Impl:
			msp1, err = (&GMFactory{}).Get(newOpts, bccsp)
		default:
			panic("unSupport bccsp type")
		}
	case *msp.IdemixNewOpts:
		msp1, err = (&IDEMIXFactory{}).Get(newOpts, bccsp)

	default:
		err = errors.New("UnSupport opts")
	}
	return msp1, err
}
