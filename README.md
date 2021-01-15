# Hyperledger Fabric [![join the chat][rocketchat-image]][rocketchat-url]

[rocketchat-url]: https://chat.hyperledger.org/channel/fabric
[rocketchat-image]: https://open.rocket.chat/images/join-chat.svg

>> 这是基于fabric-v2.2.0修改的支持国密算法的fabric，已通过命令行完成网络部署以及链码操作测试。

#### 待办事项

- [ ] TLS修改 （暂不支持TLS模式）
  - [x] 先打算TLS部分使用ECDSA调试(测试通过)
- [ ] fabric-chaincode-go 依赖库支持国密

#### 已做修改

- [x] 新增国密bccsp实现
- [x] 新增国密msp实现
- [x] peer/orderer 代码适配
- [x] 证书生成工具兼容ecdsa和gm
  - [x] cryptogen generate新增--useGM选项,需要生成国密证书时需加入这个参数(!注意这个参与不需要赋值--useGM 指定即可)

#### 疑问点
- 国密支持需要修改mspType?是否能通过增加国密bccsp实现
- bccsp实现之一的IDEMIX本质上是依赖于SW的,那么新增了GM，IDEMIX如何适配？
#### 项目测试

- 下载&编译项目
```
git clone https://github.com/ehousecy/fabric
cd fabric && git checkout develop
make native
make docker
cp build/bin/* /usr/local/bin/
# 如果是国密的话，目前还需要依赖其他cryptogen工具来替代
```
- 下载测试库
```
git clone https://github.com/hyperledger/fabric-samples
```
- 修改配置
```
# 3.1 修改fabric-samples/config下的配置文件使其支持国密
# 3.2 修改yaml文件
修改如下
orderer:  
      - ORDERER_GENERAL_TLS_ENABLED=false //禁用tls
      - ORDERER_GENERAL_LOCALMSPTYPE=GM //msp的类型,目前有bccsp、idemix和GM三种
      - ORDERER_GENERAL_BCCSP_DEFAULT=GM //bccsp实例，目前有SW、PKCS11和GM
peer:
      - CORE_PEER_TLS_ENABLED=false //禁用tls
      - CORE_PEER_LOCALMSPTYPE=GM
      - CORE_PEER_BCCSP_DEFAULT=GM           
# 3.3 修改脚本
envVar.sh：
    export CORE_PEER_LOCALMSPTYPE=GM
    export CORE_PEER_BCCSP_DEFAULT=GM
    export CORE_PEER_TLS_ENABLED=false
createChannel.sh、deployCC.sh：
    禁用tls  
# 3.4 修改configtx.yaml
将共识算法改为solo:
     OrdererType: solo
修改组织mspType:
    MSPType: GM //msp类型 bccsp/idemix/GM, 默认是bccsp，如果想切换到国密需修改为GM            
```

- 启动测试
```
cd test-network
./network.sh up -i 2.2.0
./network.sh createChannel
./network.sh deployCC -ccn fabcar -ccp ../chaincode/fabcar/go -ccl go -ccep "OR('Org1MSP.member','Org2MSP.member')" -ccv v1.0 -ccs 1
```

#### 常见问题

```
Error starting fabcar chaincode: failed to parse client key pair
#解决方案：合约依赖改为国密支持的
```
```
import cycle not allowed
package github.com/hyperledger/fabric/cmd/peer
imports github.com/hyperledger/fabric/internal/peer/chaincode
imports github.com/hyperledger/fabric/core/common/ccprovider
imports github.com/hyperledger/fabric/core/common/privdata
imports github.com/hyperledger/fabric/common/cauthdsl
imports github.com/hyperledger/fabric/common/policies
imports github.com/hyperledger/fabric/msp
imports github.com/hyperledger/fabric/msp/gm
imports github.com/hyperledger/fabric/msp
#解决方案：重新梳理代码层级结构
```
```
2021-01-04 14:50:44.253 CST [nodeCmd] serve -> FATA 01e Failed to set TLS client certificate (error parsing client TLS key pair: x509: unsupported elliptic curve)
##解决方案：暂且禁用TLS
```
```
2021-01-08 10:20:52.197 CST [orderer.common.server] reuseListener -> PANI 015 TLS is required for running ordering nodes of cluster type.
panic: TLS is required for running ordering nodes of cluster type.
#解决方案：暂时用solo共识
```
```
2021-01-11 18:18:38.572 CST [common.tools.configtxgen] main -> FATA 004 Error on inspectBlock: malformed block contents: *common.Block: error in PopulateTo for field data for message *common.Block: *commonext.BlockData: error in PopulateTo for slice field data at index 0 for message *commonext.BlockData: *commonext.Envelope: error in PopulateTo for field payload for message *commonext.Envelope: *commonext.Payload: error in PopulateTo for field data for message *commonext.Payload: *common.ConfigEnvelope: error in PopulateTo for field config for message *common.ConfigEnvelope: *commonext.Config: error in PopulateTo for field channel_group for message *commonext.Config: *commonext.DynamicChannelGroup: error in PopulateTo for map field groups and key Orderer for message *commonext.DynamicChannelGroup: *ordererext.DynamicOrdererGroup: error in PopulateTo for map field groups and key OrdererOrg for message *ordererext.DynamicOrdererGroup: *ordererext.DynamicOrdererOrgGroup: error in PopulateTo for map field values and key MSP for message *ordererext.DynamicOrdererOrgGroup: *ordererext.DynamicOrdererOrgConfigValue: error in PopulateTo for field value for message *ordererext.DynamicOrdererOrgConfigValue: *mspext.MSPConfig: error in PopulateTo for field config for message *mspext.MSPConfig: unable to decode MSP type: 3
Exiting.
#解决方案：修改mspext.MspConfig新增mspType GM
```