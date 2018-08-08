# DNSMonitoring
a python script monitor your dns server working right or not, send log to syslog server

为Linux系统开发 监控DNS服务器是否被劫持使用 基于python2.7 只需pip install dnspython
快速兼容python3 pip install dnspython3 将主函数中的print语句加上括号
## 第一个测试版本
syslog服务器的IP地址和协议在程序里是写死的，还没有进行测试和debug，没有添加异常处理。