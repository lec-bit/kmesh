## 证书申请与管理模块

## 概要

kmesh支持TLS能力需要使用由istiod签发的证书，所以需要一套证书申请与管理模块，用于申请证书并管理证书的生命周期。

## 功能

1. 为纳管pod所在的sa申请证书
2. 证书有效期到期自动刷新

## 证书申请模块

随kmesh启动创建一个caclient客户端，与istiod建立加密的grpc连接

使用workload中的信息，构造出CSR请求和私钥，将CSR请求通过caclient发送给istiod，istiod进行签名并返回证书

## 证书生命周期管理

### 设计细节

**使用一个pending优先队列和map来记录与管理证书**

penging优先队列：使用证书到期时间进行排序，保持最近到期的证书的优先度最高，定期检查最近到期的证书，提前10分钟刷新证书；

```go
优先队列元素内容：
type certExp struct {
    hostName string	//使用sa构造的证书名
    exp time.Time	//证书到期时间
}

更新时机：
	新增证书：插入一条新的记录
	刷新证书：删除旧记录，添加新记录；
	删除证书：遍历并删除旧证书的记录
```

使用map来记录证书信息和证书状态：

```go
map：记录使用该证书的pod 数量
​	key：hostName	//使用sa构造的证书名
​	value：certCache

type certCache struct {
	cert istiosecurity.SecretItem	//证书信息
    refcnt uint32 //记录使用该证书的pod数
}

更新时机：
	在某sa下第一次有pod被kmesh纳管时新增证书；新建并添加一条记录	
	在该sa下所有被kmesh纳管pod都被删除时(refCnt=0)删除证书；删除一条记录

	在证书到期自动刷新时更新value内容；刷新已有记录中的cert

	在某sa下有pod被kmesh纳管时，对应refcnt+1，记录refIp；
	在某sa下有被kmesh纳管的pod被删除时，对应refcnt-1，删除refIp；
	
生命周期：为整个sa的证书存在的时间；创建于sa证书申请时，删除于sa证书删除时


```

### 场景一：新增证书

![image-20240516223756696](C:\Users\86188\AppData\Roaming\Typora\typora-user-images\image-20240516223756696.png)



1:纳管pod1，新增workload，SecretManager查找对应sa的证书：若已存在则计数加1；若不存在则进行证书申请

2:为sa1 构造并发送CSR请求

3:istiod签发证书

4:存储证书：

- 存储证书
- 在状态信息中
  - 记录  count，为此sa进行计数，记录使用该证书的pod数量；
- 往penging优先队列中添加一条到期时间的记录

### 场景二：删除证书

![image-20240516223812058](C:\Users\86188\AppData\Roaming\Typora\typora-user-images\image-20240516223812058.png)



1:删除pod1，删除对应workload

2:该sa计数减一；

​		若此时sa计数为0，则在15s后(为了应对pod重启等情况，避免不必要的删除后立刻申请证书)删除证书：

- 遍历pending队列，删除对应的记录
- 删除sa对应的证书

### 场景三：证书到期自动更新

![image-20240516223821928](C:\Users\86188\AppData\Roaming\Typora\typora-user-images\image-20240516223821928.png)



1:pending优先队列中有效期最近的证书到期，触发证书刷新动作

2:为该证书的sa构造并发送CSR请求

3:istiod签发证书

4:存储证书，

- 刷新map中的证书；refcnt保持不变
- 在pending队列中添加一条记录

## DFX：

1. 在ambient模式下，ztunnel与kmesh各自拥有着一套证书管理体系，两者互不干扰，可能存在两者均为某sa申请了证书的情况，这种情况下流量被谁接管就使用谁的一套证书

2. kmesh异常重启情况下，旧的证书记录全部废弃，证书全部重新申请
3. sa下只有一个被纳管pod，该pod重启情况下为避免无效的证书删除与订阅，将证书删除逻辑延时15秒后进行
4. 多并发场景：
   1. 增删，到期刷新证书各有后台持续运行的一个协程去管理



### 规格

当前如果需要使用kmesh tls能力，需要在istio启动时，在CA_TRUSTED_NODE_ACCOUNTS环境变量后边添加kmesh-system/kmesh 
