---
title: 2020-12-09-Shiro rememberMe漏洞复现思路 
tags: Shiro漏洞,反序列化漏洞,思路
renderNumberedHeading: true
grammar_cjkRuby: true
---


## Apache Shiro框架介绍

>Apache Shiro是一个强大易用的Java安全框架，提供了认证、授权、加密和会话管理等功能。Shiro框架直观、易用，同时也能提供健壮的安全性。<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607520029133.png)

## Shiro rememberMe漏洞(Shiro-550)

### 漏洞原理

> Apache Shiro框架提供了记住密码的功能（RememberMe），用户登录成功后会生成经过加密并编码的cookie。在服务端对rememberMe的cookie值，先base64解码然后AES解密再反序列化，就导致了反序列化RCE漏洞。

Payload产生的过程：
>命令=>序列化=>AES加密=>base64编码=>RememberMe Cookie值

在整个漏洞利用过程中，比较重要的是AES加密的密钥，如果没有修改默认的密钥那么就很容易就知道密钥了,Payload构造起来也是十分的简单。

### 漏洞利用

> 漏洞复现的话，我们就使用Vulhub这个靶场
> 
> 下面我们来安装部署这个靶场

#### Docker安装

使用命令安装最新版Docker `curl -s https://get.docker.com/ | sh`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607521706683.png)

安装成功之后我们启动一下Docker服务 `systemctl start docker`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607521949131.png)

然后安装 `compose` 工具 `pip3 install docker-compose`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607522350868.png)

#### Vulhub靶场

> Vulhub是一个面向大众的开源漏洞靶场，无需docker知识，简单执行两条命令即可编译、运行一个完整的漏洞靶场镜像。
><br>
>Github地址：https://github.com/vulhub/vulhub

使用 `git clone` 命令下载靶场<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607522744091.png)

切换到Vulhub目录<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607523058216.png)

选择自己需要的靶场，我这里就选Shiro<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607523173974.png)

每个靶场里面都有对应的README.md说明文档，也有复现思路

我们使用 `docker-compose up -d ` 命令来下发和启动靶场<br>

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607523316725.png)

可以使用 ` dcoker ps ` 查看当前正在运行的靶场<br>

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607523391314.png)

我们就把漏洞环境搭建完成了

#### 工具利用

>ShiroExploit：
>支持对Shiro550（硬编码秘钥）和Shiro721（Padding Oracle）的一键化检测，支持多种回显方式
><br>
>Github地址：https://github.com/feihong-cs/ShiroExploit-Deprecated

访问一下我们docker搭建的漏洞环境<br>
![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607524512295.png)

**Shiro漏洞特征返回包中包含 `rememberMe=deleteMe`字段。**

我们抓包看下返回包内容<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607524746992.png)

可以看到返回包有`Set-Cookie: rememberMe=deleteMe;`字段

打开ShiroExploit工具，选择漏洞类型`Shiro550`，填写目标地址<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607525022023.png)

然后点击下一步<br>
![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607525187135.png)

> **选择使用 ceye.io 进行漏洞检测**
> - 可以不进行任何配置，配置文件中已经预置了 CEYE 域名和对应的 Token，当然也可以对其进行修改。
> - 程序会首先使用 URLDNS 筛选出唯一 Key，然后依次调用各个 Gadget 生成 Payload
> - 缺点：程序会使用 API：http://api.ceye.io/v1/records?token=a78a1cb49d91fe09e01876078d1868b2&type=dns&filter=[UUID] 查询检测结果，这个 API 有时候会无法正常访问，导致在这种方式下无法找到 Key 或者有效的 Gadget
>
>**选择 使用 dnslog.cn 进行漏洞检测**
> - 可以不进行任何配置，每次启动时程序会自动从 dnslog.cn 申请一个 DNS Record。
> - 程序会首先使用 URLDNS 筛选出唯一 Key，然后依次调用各个 Gadget 生成 Payload
> - 缺点：少数时候 dnslog.cn 会间隔较久才显示 DNS 解析结果导致程序无法找到 Key 或者有效的 Gadget，且 dnslog.cn 只会记录最近的10条 DNS 解析记录
> 
>**选择 使用 JRMP + dnslog 进行漏洞检测**
> - 需要在 VPS 上通过命令`java -cp ShiroExploit.jar com.shiroexploit.server.BasicHTTPServer [HttpSerivce Port] [JRMPListener Port]`开启HttpService/JRMPListener，并按照要求填入相应 IP 和端口
> - 如果开启 HttpService/JRMPListener 时未指定端口号，则 `HTTPService `默认监听 `8080` 端口，`JRMPListener` 默认监听 `8088` 端口
> - 使用 `JRMP` 的方式进行漏洞检测，可以显著减小 cookie 大小
> - 程序会首先使用 `URLDNS` 筛选出唯一 Key，然后使用 JRMP 依次为各个 Gadget 生成对应的 JRMPListener
> 
>**选择 使用回显进行漏洞检测**
> - 针对不出网的情况进行漏洞检测，此时可以检测的 Gadget 类型会少于使用 DNSLog 方式的 Gadget类型
> - 目前主要是通过将命令执行结果写入 Web 目录下然后读取的方式实现回显
> - 需要提供一个静态资源 URL，程序会将此静态资源所在的目录当做写入目录
> - 注：开始的时候使用 https://blog.csdn.net/fnmsd/article/details/106709736 介绍的方式实现回显，在本地可以测试成功，但是在实际环境中基本不成功（可能是我的姿势有问题，欢迎探讨），所以目前是通过读写文件的方式实现回显，后期可能会加入其它方式

我在这就选择`ceye.io`进行检测，然后点下一步它就自动开始检测漏洞<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607526707898.png)

然后直接反弹一个shell<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607526779161.png)

格式为`IP:Port`

然后在VPS上监听你要反弹的端口<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607526915116.png)

反弹成功<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1607527239304.png)




