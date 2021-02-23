# Hyperledger Fabric 国密版
>> 这是基于fabric 2.2修改的支持国密算法的fabric，已通过命令行完成网络部署以及链码操作测试。

## 简介
本项目涵盖 Fabric、Fabric CA、 Fabric SDK和fabric-chaincode-go 的全链路国密改造

## 相关项目
* [国密化CA](https://github.com/ehousecy/fabric-ca)
* [国密化GO-SDK](https://github.com/ehousecy/fabric-sdk-go)
* [国密化FABRIC-CHAINCODE-GO](https://github.com/ehousecy/fabric-chaincode-go)

## 改造思路
- [x] bccsp增加国密支持
- [x] 证书生成工具兼容ecdsa和gm
    - [x] cryptogen generate新增--useGM选项,需要生成国密证书时需加入这个参数(!注意这个参与不需要赋值--useGM 指定即可)
    - [x] cryptogen generate新增--useGMTLS选项,需要生成国密TLS证书时需加入这个参数(!注意这个参与不需要赋值--useGMTLS 指定即可)
- [x] 引用替换。主要是crypto/x509和crypto/tls的替换
- [x] TLS国密支持
    - [x] 修改思路
        - [x] 以Credential作为修改入口，首先修改pkg/comm下的client、server和connection等文件,然后引用的地方做修改和兼容
        - [x] 增加grpc credential实现  
        - [x] x509.Certificate和x509.newCertPool()相关的地方做适配
        - [x] tls加密套件增加国密支持
- [x] 智能合约交互增加国密支持
  - [x] 自签名TLS根证书增加国密支持
- [x] 代码适配

## 项目测试

#### 1. 下载&编译项目
```
# 下载fabric-ca项目，编译并拷贝可执行文件
git clone https://github.com/ehousecy/fabric-ca
cd fabric-ca && git checkout ccs-gm
make native && make make docker
cp bin/* /usr/local/bin/

# 下载fabric项目，编译并拷贝可执行文件
git clone https://github.com/ehousecy/fabric
cd fabric && git checkout develop
make native && make docker
cp build/bin/* /usr/local/bin/
```

#### 2. 生成证书(fabric-ca专用，使用cryptogen可跳过)
- fabric-ca-server
```
# 启动时重写如下环境变量：
FABRIC_CA_SERVER_CSR_KEYREQUEST_ALGO=gmsm2 //默认是ecdsa
FABRIC_CA_SERVER_CSR_KEYREQUEST_SIZE=256   //默认是256
```
- fabric-ca-client
```
# 客户端 register/enroll/reenroll... 需指定keyRequest的算法和大小(默认是ecdsa/256)
--csr.keyrequest.algo gmsm2 --csr.keyrequest.size 256
```

#### 3. 下载测试库及配置
```
git clone https://github.com/hyperledger/fabric-samples
```
###### 3.1 修改配置
- 使用fabric-ca签发的证书
```
# 将证书拷贝到fabric-samples/test-network/organizations/下，然后轻量修改network.sh脚本
function networkUp() {

  checkPrereqs
  # generate artifacts if they don't exist
  if [ ! -d "organizations/peerOrganizations" ]; then
    createOrgs
  fi
  generateCCP
```
- 使用cryptogen
```
# 生成国密密钥及证书
network.sh:
    cryptogen generate 加上--useGM --useGMTLS
```

###### 3.2 修改智能合约
```
# 3.2.1 修改fabric-samples/chaincode/fabcar/go/go.mod
# 3.2.1.1 首先通过命令获取fabric-chaincode-go版本号
go get github.com/ehousecy/fabric-chaincode-go@ccs-gm
# 3.2.1.2 go.mod添加replace
replace (
	github.com/hyperledger/fabric-chaincode-go => github.com/ehousecy/fabric-chaincode-go v0.0.0-20210223060054-45621447fc36
)
```

#### 4. 初始化区块链网络
```
cd test-network
./network.sh up -i 2.2.0
./network.sh createChannel
./network.sh deployCC -ccn fabcar -ccp ../chaincode/fabcar/go -ccl go -ccep "OR('Org1MSP.member','Org2MSP.member')" -ccv v1.0 -ccs 1
```

#### 5. SDK调用

###### 5.1 使用fabric-sampels/fabcar/go 作为示例

###### 5.2 修改脚本runfabcar.sh,编译时指定单证书模式
```
go run -tags=single_cert fabcar.go
```
###### 5.3 调用
```
sh runfabcar.sh
```
###### 5.4 如果想使用go-sdk ca部分功能，可以参考如下代码:
```
func registerAndEnroll() error{
	userCertPath := filepath.Join(".",name+"@Org1MSP-cert.pem")
	if exist,_ :=PathExists(userCertPath); exist{
		log.Printf("User :%s exist ,skip enroll", name)
		return nil
	}
	ccpPath := filepath.Join(
		"..",
		"..",
		"test-network",
		"organizations",
		"peerOrganizations",
		"org1.example.com",
		"connection-org1.yaml",
	)
	sdk, err := fabsdk.New(config.FromFile(ccpPath))
	if err != nil{
		return fmt.Errorf("Create sdk instance failed %s",err)
	}

	// Get the Client.
	// Without WithOrg option, uses default client organization.
	caClient, err := caclient.New(sdk.Context())
	if err != nil{
		return fmt.Errorf("Create caClient failed %s",err)
	}
	_, err = caClient.Register(&caclient.RegistrationRequest{Name: name,Secret: "123456"})

	if err != nil{
		return fmt.Errorf("Register failed %s",err)
	}
    
	err = caClient.Enroll(name, caclient.WithSecret("123456"), caclient.WithCSR(&caclient.CSRInfo{
		KeyRequest: &caclient.KeyRequest{
			Algo: "gmsm2",
			Size: 256,
		},
	}))
	if err != nil{
		return fmt.Errorf("Enroll failed %s",err)
	}
	return nil
}
```


## 常见问题

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
2021-01-20 02:12:34.480 UTC [chaincode.accesscontrol] authenticate -> WARN 230e TLS is active but chaincode fabcar_v1.0:38e9938f7924ada1c42cbcc1e406c77ad2a52f771cf8fe550360b09a307d17f3 didn't send certificate
#解决方案：credentials类型出现了问题，需替换成gmcredentials
```

## 关于我们
国密化改造工作主要由ehousecy完成，想要了解更多/商业合作/联系我们，欢迎访问我们的[官网](https://ebaas.com/)。

