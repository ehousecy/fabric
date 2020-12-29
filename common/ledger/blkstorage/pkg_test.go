/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blkstorage

import (
	"io/ioutil"
	"math"
	"os"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/ehousecy/fabric/common/flogging"
	"github.com/ehousecy/fabric/common/metrics"
	"github.com/ehousecy/fabric/common/metrics/disabled"
	"github.com/ehousecy/fabric/protoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	flogging.ActivateSpec("blkstorage=debug")
	os.Exit(m.Run())
}

func testPath() string {
	if path, err := ioutil.TempDir("", "blkstorage-"); err != nil {
		panic(err)
	} else {
		return path
	}
}

type testEnv struct {
	t        testing.TB
	provider *BlockStoreProvider
}

var attrsToIndex = []IndexableAttr{
	IndexableAttrBlockHash,
	IndexableAttrBlockNum,
	IndexableAttrTxID,
	IndexableAttrBlockNumTranNum,
}

func newTestEnv(t testing.TB, conf *Conf) *testEnv {
	return newTestEnvWithMetricsProvider(t, conf, &disabled.Provider{})
}

func newTestEnvWithMetricsProvider(t testing.TB, conf *Conf, metricsProvider metrics.Provider) *testEnv {
	return newTestEnvSelectiveIndexing(t, conf, attrsToIndex, metricsProvider)
}

func newTestEnvSelectiveIndexing(t testing.TB, conf *Conf, attrsToIndex []IndexableAttr, metricsProvider metrics.Provider) *testEnv {
	indexConfig := &IndexConfig{AttrsToIndex: attrsToIndex}
	p, err := NewProvider(conf, indexConfig, metricsProvider)
	assert.NoError(t, err)
	return &testEnv{t, p}
}

func (env *testEnv) Cleanup() {
	env.provider.Close()
	env.removeFSPath()
}

func (env *testEnv) removeFSPath() {
	fsPath := env.provider.conf.blockStorageDir
	os.RemoveAll(fsPath)
}

type testBlockfileMgrWrapper struct {
	t            testing.TB
	blockfileMgr *blockfileMgr
}

func newTestBlockfileWrapper(env *testEnv, ledgerid string) *testBlockfileMgrWrapper {
	blkStore, err := env.provider.Open(ledgerid)
	assert.NoError(env.t, err)
	return &testBlockfileMgrWrapper{env.t, blkStore.fileMgr}
}

func (w *testBlockfileMgrWrapper) addBlocks(blocks []*common.Block) {
	for _, blk := range blocks {
		err := w.blockfileMgr.addBlock(blk)
		assert.NoError(w.t, err, "Error while adding block to blockfileMgr")
	}
}

func (w *testBlockfileMgrWrapper) testGetBlockByHash(blocks []*common.Block, expectedErr error) {
	for i, block := range blocks {
		hash := protoutil.BlockHeaderHash(block.Header)
		b, err := w.blockfileMgr.retrieveBlockByHash(hash)
		if expectedErr != nil {
			assert.Error(w.t, err, expectedErr.Error())
			continue
		}
		assert.NoError(w.t, err, "Error while retrieving [%d]th block from blockfileMgr", i)
		assert.Equal(w.t, block, b)
	}
}

func (w *testBlockfileMgrWrapper) testGetBlockByNumber(blocks []*common.Block, startingNum uint64, expectedErr error) {
	for i := 0; i < len(blocks); i++ {
		b, err := w.blockfileMgr.retrieveBlockByNumber(startingNum + uint64(i))
		if expectedErr != nil {
			assert.Equal(w.t, err.Error(), expectedErr.Error())
			continue
		}
		assert.NoError(w.t, err, "Error while retrieving [%d]th block from blockfileMgr", i)
		assert.Equal(w.t, blocks[i], b)
	}
	// test getting the last block
	b, err := w.blockfileMgr.retrieveBlockByNumber(math.MaxUint64)
	iLastBlock := len(blocks) - 1
	assert.NoError(w.t, err, "Error while retrieving last block from blockfileMgr")
	assert.Equal(w.t, blocks[iLastBlock], b)
}

func (w *testBlockfileMgrWrapper) testGetBlockByTxID(blocks []*common.Block, expectedErr error) {
	for i, block := range blocks {
		for _, txEnv := range block.Data.Data {
			txID, err := protoutil.GetOrComputeTxIDFromEnvelope(txEnv)
			assert.NoError(w.t, err)
			b, err := w.blockfileMgr.retrieveBlockByTxID(txID)
			if expectedErr != nil {
				assert.Equal(w.t, err.Error(), expectedErr.Error())
				continue
			}
			assert.NoError(w.t, err, "Error while retrieving [%d]th block from blockfileMgr", i)
			assert.Equal(w.t, block, b)
		}
	}
}

func (w *testBlockfileMgrWrapper) testGetTransactionByTxID(txID string, expectedEnvelope []byte, expectedErr error) {
	envelope, err := w.blockfileMgr.retrieveTransactionByID(txID)
	if expectedErr != nil {
		assert.Equal(w.t, err.Error(), expectedErr.Error())
		return
	}
	actualEnvelope, err := proto.Marshal(envelope)
	assert.NoError(w.t, err)
	assert.Equal(w.t, expectedEnvelope, actualEnvelope)
}

func (w *testBlockfileMgrWrapper) testGetMultipleDataByTxID(
	txID string,
	expectedData []*expectedBlkTxValidationCode,
) {
	rangescan := constructTxIDRangeScan(txID)
	itr, err := w.blockfileMgr.db.GetIterator(rangescan.startKey, rangescan.stopKey)
	require := require.New(w.t)
	require.NoError(err)
	defer itr.Release()

	fetchedData := []*expectedBlkTxValidationCode{}
	for itr.Next() {
		v := &TxIDIndexValue{}
		require.NoError(proto.Unmarshal(itr.Value(), v))

		blkFLP := &fileLocPointer{}
		require.NoError(blkFLP.unmarshal(v.BlkLocation))
		blk, err := w.blockfileMgr.fetchBlock(blkFLP)
		require.NoError(err)

		txFLP := &fileLocPointer{}
		require.NoError(txFLP.unmarshal(v.TxLocation))
		txEnv, err := w.blockfileMgr.fetchTransactionEnvelope(txFLP)
		require.NoError(err)

		fetchedData = append(fetchedData, &expectedBlkTxValidationCode{
			blk:            blk,
			txEnv:          txEnv,
			validationCode: peer.TxValidationCode(v.TxValidationCode),
		})
	}
	require.Equal(expectedData, fetchedData)
}

func (w *testBlockfileMgrWrapper) close() {
	w.blockfileMgr.close()
}

type expectedBlkTxValidationCode struct {
	blk            *common.Block
	txEnv          *common.Envelope
	validationCode peer.TxValidationCode
}
