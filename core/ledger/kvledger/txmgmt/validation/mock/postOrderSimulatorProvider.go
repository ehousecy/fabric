// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	"sync"

	"github.com/ehousecy/fabric/core/ledger"
)

type PostOrderSimulatorProvider struct {
	NewTxSimulatorStub        func(string) (ledger.TxSimulator, error)
	newTxSimulatorMutex       sync.RWMutex
	newTxSimulatorArgsForCall []struct {
		arg1 string
	}
	newTxSimulatorReturns struct {
		result1 ledger.TxSimulator
		result2 error
	}
	newTxSimulatorReturnsOnCall map[int]struct {
		result1 ledger.TxSimulator
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *PostOrderSimulatorProvider) NewTxSimulator(arg1 string) (ledger.TxSimulator, error) {
	fake.newTxSimulatorMutex.Lock()
	ret, specificReturn := fake.newTxSimulatorReturnsOnCall[len(fake.newTxSimulatorArgsForCall)]
	fake.newTxSimulatorArgsForCall = append(fake.newTxSimulatorArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("NewTxSimulator", []interface{}{arg1})
	fake.newTxSimulatorMutex.Unlock()
	if fake.NewTxSimulatorStub != nil {
		return fake.NewTxSimulatorStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.newTxSimulatorReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *PostOrderSimulatorProvider) NewTxSimulatorCallCount() int {
	fake.newTxSimulatorMutex.RLock()
	defer fake.newTxSimulatorMutex.RUnlock()
	return len(fake.newTxSimulatorArgsForCall)
}

func (fake *PostOrderSimulatorProvider) NewTxSimulatorCalls(stub func(string) (ledger.TxSimulator, error)) {
	fake.newTxSimulatorMutex.Lock()
	defer fake.newTxSimulatorMutex.Unlock()
	fake.NewTxSimulatorStub = stub
}

func (fake *PostOrderSimulatorProvider) NewTxSimulatorArgsForCall(i int) string {
	fake.newTxSimulatorMutex.RLock()
	defer fake.newTxSimulatorMutex.RUnlock()
	argsForCall := fake.newTxSimulatorArgsForCall[i]
	return argsForCall.arg1
}

func (fake *PostOrderSimulatorProvider) NewTxSimulatorReturns(result1 ledger.TxSimulator, result2 error) {
	fake.newTxSimulatorMutex.Lock()
	defer fake.newTxSimulatorMutex.Unlock()
	fake.NewTxSimulatorStub = nil
	fake.newTxSimulatorReturns = struct {
		result1 ledger.TxSimulator
		result2 error
	}{result1, result2}
}

func (fake *PostOrderSimulatorProvider) NewTxSimulatorReturnsOnCall(i int, result1 ledger.TxSimulator, result2 error) {
	fake.newTxSimulatorMutex.Lock()
	defer fake.newTxSimulatorMutex.Unlock()
	fake.NewTxSimulatorStub = nil
	if fake.newTxSimulatorReturnsOnCall == nil {
		fake.newTxSimulatorReturnsOnCall = make(map[int]struct {
			result1 ledger.TxSimulator
			result2 error
		})
	}
	fake.newTxSimulatorReturnsOnCall[i] = struct {
		result1 ledger.TxSimulator
		result2 error
	}{result1, result2}
}

func (fake *PostOrderSimulatorProvider) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.newTxSimulatorMutex.RLock()
	defer fake.newTxSimulatorMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *PostOrderSimulatorProvider) recordInvocation(key string, args []interface{}) {
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
