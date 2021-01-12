package factory

import (
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/msp"
	"github.com/pkg/errors"
)

type MSPFactory interface {

	// Name returns the name of this factory
	Name() string

	// Get returns an instance of MSP using opts.
	Get(bccsp bccsp.BCCSP) (msp.MSP, error)
}

func GetDefault(newOpts msp.NewOpts,bccsp bccsp.BCCSP) (msp.MSP,error){
	var msp1 msp.MSP
	var err error
	switch newOpts.(type) {
		case *msp.BCCSPNewOpts:
			msp1,err = (&SWFactory{}).Get(bccsp)
		case *msp.GMNewOpts:
			msp1,err = (&GMFactory{}).Get(bccsp)
	default:
		err = errors.New("UnSupport opts")
	}
	return msp1,err
}