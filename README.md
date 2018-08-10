# DNSMonitoring
a python script monitor your dns server working right or not, send log to syslog server

为Linux系统开发 监控DNS服务器是否被劫持使用 基于python3

pip install dnspython3
请将参照域名和ip写入一个文本文档放到和python文件相同目录下
格式为：
域名:IP
如 www.example.com:1.1.1.1
不要用多余空行
监控一个域名 每小时生成的日志大小为0.14M
用法 python3 dns_test.py -t data.txt --ds 8.8.8.8 --dp 53 --ss 192.168.1.1 --sp 514

## 第一个测试版本

syslog服务器的IP地址和协议在程序里是写死的，还没有进行测试和debug，没有添加异常处理。

##第二个版本

syslog服务器ip和端口在命令行中输入，添加了很多因人工失误而导致的异常处理，还有dns请求超时防止程序卡死的异常处理

因为客户网站没有CDN 所以程序目前只支持一个域名对应一个IP



