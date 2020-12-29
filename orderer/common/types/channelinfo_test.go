/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package types_test

import (
	"encoding/json"
	"testing"

	"github.com/ehousecy/fabric/orderer/common/types"
	"github.com/stretchr/testify/assert"
)

func TestErrorResponse(t *testing.T) {
	errResp := types.ErrorResponse{Error: "oops"}

	buff, err := json.Marshal(errResp)
	assert.NoError(t, err)
	assert.Equal(t, `{"error":"oops"}`, string(buff))

	buff2 := []byte(`{"error":"oops again"}`)
	errResp2 := types.ErrorResponse{}
	err = json.Unmarshal(buff2, &errResp2)
	assert.NoError(t, err)
	assert.NotNil(t, errResp2)
	assert.Equal(t, "oops again", errResp2.Error)
}

func TestChannelInfoShort(t *testing.T) {
	info := types.ChannelInfoShort{
		Name: "my-channel",
		URL:  "/api/v1/channels/my-channel",
	}

	buff, err := json.Marshal(info)
	assert.NoError(t, err)
	assert.Equal(t, `{"name":"my-channel","url":"/api/v1/channels/my-channel"}`, string(buff))

	buff2 := []byte(`{"name":"my-channel2","url":"/api/v1/channels/my-channel2"}`)
	var info2 types.ChannelInfoShort
	err = json.Unmarshal(buff2, &info2)
	assert.NoError(t, err)
	assert.NotNil(t, info2)
	assert.Equal(t, "my-channel2", info2.Name)
	assert.Equal(t, "/api/v1/channels/my-channel2", info2.URL)

	buff3 := []byte(`{"name":"my-channel2","url":"/api/v1/channels/my-channel3","oops"}`)
	var info3 types.ChannelInfoShort
	err = json.Unmarshal(buff3, &info3)
	assert.Error(t, err)
}

func TestChannelList(t *testing.T) {
	list := types.ChannelList{SystemChannel: nil, Channels: nil}

	buff, err := json.Marshal(list)
	assert.NoError(t, err)
	assert.Equal(t, `{"systemChannel":null,"channels":null}`, string(buff))

	list.SystemChannel = &types.ChannelInfoShort{Name: "s", URL: "/api/channels/s"}
	list.Channels = []types.ChannelInfoShort{
		{Name: "a", URL: "/api/channels/a"},
		{Name: "b", URL: "/api/channels/b"},
	}

	buff, err = json.Marshal(list)
	assert.NoError(t, err)
	assert.Equal(t, `{"systemChannel":{"name":"s","url":"/api/channels/s"},"channels":[{"name":"a","url":"/api/channels/a"},{"name":"b","url":"/api/channels/b"}]}`, string(buff))
}

func TestChannelInfo(t *testing.T) {
	info := types.ChannelInfo{
		Name:            "a",
		URL:             "/api/channels/a",
		ClusterRelation: types.ClusterRelationFollower,
		Status:          types.StatusActive,
		Height:          uint64(1) << 60,
	}

	buff, err := json.Marshal(info)
	assert.NoError(t, err)
	assert.Equal(t, `{"name":"a","url":"/api/channels/a","clusterRelation":"follower","status":"active","height":1152921504606846976}`, string(buff))

	var info2 types.ChannelInfo
	err = json.Unmarshal(buff, &info2)
	assert.NoError(t, err)
	assert.Equal(t, info.Height, info2.Height)
}
