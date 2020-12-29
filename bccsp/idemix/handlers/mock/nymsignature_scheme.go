// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	"sync"

	"github.com/ehousecy/fabric/bccsp/idemix/handlers"
)

type NymSignatureScheme struct {
	SignStub        func(handlers.Big, handlers.Ecp, handlers.Big, handlers.IssuerPublicKey, []byte) ([]byte, error)
	signMutex       sync.RWMutex
	signArgsForCall []struct {
		arg1 handlers.Big
		arg2 handlers.Ecp
		arg3 handlers.Big
		arg4 handlers.IssuerPublicKey
		arg5 []byte
	}
	signReturns struct {
		result1 []byte
		result2 error
	}
	signReturnsOnCall map[int]struct {
		result1 []byte
		result2 error
	}
	VerifyStub        func(handlers.IssuerPublicKey, handlers.Ecp, []byte, []byte) error
	verifyMutex       sync.RWMutex
	verifyArgsForCall []struct {
		arg1 handlers.IssuerPublicKey
		arg2 handlers.Ecp
		arg3 []byte
		arg4 []byte
	}
	verifyReturns struct {
		result1 error
	}
	verifyReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *NymSignatureScheme) Sign(arg1 handlers.Big, arg2 handlers.Ecp, arg3 handlers.Big, arg4 handlers.IssuerPublicKey, arg5 []byte) ([]byte, error) {
	var arg5Copy []byte
	if arg5 != nil {
		arg5Copy = make([]byte, len(arg5))
		copy(arg5Copy, arg5)
	}
	fake.signMutex.Lock()
	ret, specificReturn := fake.signReturnsOnCall[len(fake.signArgsForCall)]
	fake.signArgsForCall = append(fake.signArgsForCall, struct {
		arg1 handlers.Big
		arg2 handlers.Ecp
		arg3 handlers.Big
		arg4 handlers.IssuerPublicKey
		arg5 []byte
	}{arg1, arg2, arg3, arg4, arg5Copy})
	fake.recordInvocation("Sign", []interface{}{arg1, arg2, arg3, arg4, arg5Copy})
	fake.signMutex.Unlock()
	if fake.SignStub != nil {
		return fake.SignStub(arg1, arg2, arg3, arg4, arg5)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.signReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *NymSignatureScheme) SignCallCount() int {
	fake.signMutex.RLock()
	defer fake.signMutex.RUnlock()
	return len(fake.signArgsForCall)
}

func (fake *NymSignatureScheme) SignCalls(stub func(handlers.Big, handlers.Ecp, handlers.Big, handlers.IssuerPublicKey, []byte) ([]byte, error)) {
	fake.signMutex.Lock()
	defer fake.signMutex.Unlock()
	fake.SignStub = stub
}

func (fake *NymSignatureScheme) SignArgsForCall(i int) (handlers.Big, handlers.Ecp, handlers.Big, handlers.IssuerPublicKey, []byte) {
	fake.signMutex.RLock()
	defer fake.signMutex.RUnlock()
	argsForCall := fake.signArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3, argsForCall.arg4, argsForCall.arg5
}

func (fake *NymSignatureScheme) SignReturns(result1 []byte, result2 error) {
	fake.signMutex.Lock()
	defer fake.signMutex.Unlock()
	fake.SignStub = nil
	fake.signReturns = struct {
		result1 []byte
		result2 error
	}{result1, result2}
}

func (fake *NymSignatureScheme) SignReturnsOnCall(i int, result1 []byte, result2 error) {
	fake.signMutex.Lock()
	defer fake.signMutex.Unlock()
	fake.SignStub = nil
	if fake.signReturnsOnCall == nil {
		fake.signReturnsOnCall = make(map[int]struct {
			result1 []byte
			result2 error
		})
	}
	fake.signReturnsOnCall[i] = struct {
		result1 []byte
		result2 error
	}{result1, result2}
}

func (fake *NymSignatureScheme) Verify(arg1 handlers.IssuerPublicKey, arg2 handlers.Ecp, arg3 []byte, arg4 []byte) error {
	var arg3Copy []byte
	if arg3 != nil {
		arg3Copy = make([]byte, len(arg3))
		copy(arg3Copy, arg3)
	}
	var arg4Copy []byte
	if arg4 != nil {
		arg4Copy = make([]byte, len(arg4))
		copy(arg4Copy, arg4)
	}
	fake.verifyMutex.Lock()
	ret, specificReturn := fake.verifyReturnsOnCall[len(fake.verifyArgsForCall)]
	fake.verifyArgsForCall = append(fake.verifyArgsForCall, struct {
		arg1 handlers.IssuerPublicKey
		arg2 handlers.Ecp
		arg3 []byte
		arg4 []byte
	}{arg1, arg2, arg3Copy, arg4Copy})
	fake.recordInvocation("Verify", []interface{}{arg1, arg2, arg3Copy, arg4Copy})
	fake.verifyMutex.Unlock()
	if fake.VerifyStub != nil {
		return fake.VerifyStub(arg1, arg2, arg3, arg4)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.verifyReturns
	return fakeReturns.result1
}

func (fake *NymSignatureScheme) VerifyCallCount() int {
	fake.verifyMutex.RLock()
	defer fake.verifyMutex.RUnlock()
	return len(fake.verifyArgsForCall)
}

func (fake *NymSignatureScheme) VerifyCalls(stub func(handlers.IssuerPublicKey, handlers.Ecp, []byte, []byte) error) {
	fake.verifyMutex.Lock()
	defer fake.verifyMutex.Unlock()
	fake.VerifyStub = stub
}

func (fake *NymSignatureScheme) VerifyArgsForCall(i int) (handlers.IssuerPublicKey, handlers.Ecp, []byte, []byte) {
	fake.verifyMutex.RLock()
	defer fake.verifyMutex.RUnlock()
	argsForCall := fake.verifyArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3, argsForCall.arg4
}

func (fake *NymSignatureScheme) VerifyReturns(result1 error) {
	fake.verifyMutex.Lock()
	defer fake.verifyMutex.Unlock()
	fake.VerifyStub = nil
	fake.verifyReturns = struct {
		result1 error
	}{result1}
}

func (fake *NymSignatureScheme) VerifyReturnsOnCall(i int, result1 error) {
	fake.verifyMutex.Lock()
	defer fake.verifyMutex.Unlock()
	fake.VerifyStub = nil
	if fake.verifyReturnsOnCall == nil {
		fake.verifyReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.verifyReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *NymSignatureScheme) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.signMutex.RLock()
	defer fake.signMutex.RUnlock()
	fake.verifyMutex.RLock()
	defer fake.verifyMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *NymSignatureScheme) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ handlers.NymSignatureScheme = new(NymSignatureScheme)
