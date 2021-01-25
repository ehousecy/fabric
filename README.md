# Hyperledger Fabric [![join the chat][rocketchat-image]][rocketchat-url]

[rocketchat-url]: https://chat.hyperledger.org/channel/fabric
[rocketchat-image]: https://open.rocket.chat/images/join-chat.svg

>> 这是基于fabric-v2.2.0修改的支持国密算法的fabric，已通过命令行完成网络部署以及链码操作测试。

#### 待办事项

- [ ] TLS修改 （暂不支持TLS模式）
  - [x] 修改思路
    - [x] 以Credential作为修改入口，首先修改pkg/comm下的client、server和connection等文件,然后引用的地方做修改和兼容
    - [x] x509.Certificate和x509.newCertPool()相关的地方做适配
    - [x] 合约部分自签名证书做适配，支持gm
      - [x] peer节点启动时会生成自签名TLS根证书，然后智能合约启动时会签发TLS客户端证书
  - [x] 先打算TLS部分使用ECDSA调试(测试通过)
  - [x] 国密TLS开关设定 目前通过peer/orderer tls根证书和bccsp类型来判断
  - [x] 智能合约tls通信没有异常
    - [x] peer与智能合约通信使用的是自签名的ecdsa秘钥对
       - [x] 扩展CA，支持sm2秘钥对
          - [x] Error starting fabcar chaincode: failed to parse client key pair
  - [x] 证书混用报错
    - [x] 国密证书 + ECDSA TLS证书 验证通过
    - [x] ECDSA证书 + 国密TLS 证书 会在setup的时候报错(mspimpl无法解析gmtls证书，算已知问题吧，这里仅做测试，后续签名证书和TLS证书会做成一致的)
  - [x] 判断是否为SM证书或者GM模式
    - [x] 通过证书签名算法是否为SM2WithSM3来判断
  - [ ] 共识切换为raft
     - [x] IsConsenterOfChannel 报错 crypto.CertificatesWithSamePublicKey 做适配
     - [x] ValidateConsensusMetadata 报错 createX509VerifyOptions,VerifyConfigMetadata,validateConsenterTLSCerts 需要做适配
     - [ ] 多排序节点测试 
- [ ] fabric-chaincode-go 依赖库支持国密
  - [x] shim
    - [x] TLS credentials 适配
  - [ ] pkg
- [x] mspType GM 删除
   - [x] 调用处修改：loadLocalMSP 引用，opts, found := msp.Options[conf.General.LocalMSPType]
   - [x] msp配置中type类型改回fabric
   - [x] 通过配置加载/解析localMsp处修改适配方式

#### 已做修改

- [x] 新增国密bccsp实现
- [x] 新增国密msp实现
- [x] peer/orderer 代码适配
- [x] 证书生成工具兼容ecdsa和gm
  - [x] cryptogen generate新增--useGM选项,需要生成国密证书时需加入这个参数(!注意这个参与不需要赋值--useGM 指定即可)
  - [x] cryptogen generate新增--useGMTLS选项,需要生成国密TLS证书时需加入这个参数(!注意这个参与不需要赋值--useGMTLS 指定即可)

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
      - ORDERER_GENERAL_BCCSP_DEFAULT=GM //bccsp实例，目前有SW、PKCS11和GM
peer:
      - CORE_PEER_BCCSP_DEFAULT=GM           
# 3.3 修改脚本
envVar.sh：
    export CORE_PEER_BCCSP_DEFAULT=GM
createChannel.sh、deployCC.sh：
network.sh:
    cryptogen generate 加上--useGM
    禁用tls  
# 3.4 修改configtx.yaml
修改组织mspType:
    MSPType: GM //msp类型 bccsp/idemix/GM, 默认是bccsp，如果想切换到国密需修改为GM            
```

- 修改智能合约
```
# 4.1 修改go.mod
# 4.1.1 首先通过命令获取fabric-chaincode-go版本号
go get github.com/ehousecy/fabric-chaincode-go@master
# 4.1.2 go.mod添加replace
replace (
	github.com/hyperledger/fabric-chaincode-go => github.com/ehousecy/fabric-chaincode-go v0.0.0-20210122024824-3b16b5f9d519
)
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
```
2021-01-20 02:12:34.480 UTC [chaincode.accesscontrol] authenticate -> WARN 230e TLS is active but chaincode fabcar_v1.0:38e9938f7924ada1c42cbcc1e406c77ad2a52f771cf8fe550360b09a307d17f3 didn't send certificate
#解决方案：credentials类型出现了问题，需替换成gmcredentials
```

```
remote tls : bad certificate
# tls握手调试
grpc/server.go handleRawConn
```