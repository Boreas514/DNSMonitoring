# -*- coding: utf-8 -*-
import optparse
import socket
import re
import time
from queue import Queue, Empty
from threading import Thread
import logging
import logging.handlers
import dns.message
import dns.query
from datetime import datetime


class DNSSurveillance(object):
    def __init__(self, text_name, dns_server, dns_port, syslog_server, syslog_port):
        self.dns_dict = {}
        self.text_name = text_name
        self.DNS_SERVER = dns_server
        self.DNS_PORT = dns_port
        self.IP_RE_PA = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        self.SYSLOG_SERVER = syslog_server
        self.SYSLOG_PORT = syslog_port
        self.logger = logging.getLogger('DNS Surveillance Logger')
        self.logger.setLevel(logging.INFO)
        self.handler = logging.handlers.SysLogHandler(
            address=(self.SYSLOG_SERVER, self.SYSLOG_PORT),
            facility=logging.handlers.SysLogHandler.LOG_LOCAL6,
            socktype=socket.SOCK_DGRAM)
        self.formatter = logging.Formatter(
            'DNS Surveillance: asci_time:%(asctime)s, level_name:%(levelname)s, message:%(message)s')
        self.handler.formatter = self.formatter
        self.logger.addHandler(self.handler)
        self.work_queue = Queue()

    def init_dict(self):
        while True:
            bias = 0
            self.dns_dict = {}
            with open(self.text_name, 'r') as standard_file:
                for line in standard_file:
                    line.replace('：', ':')
                    # 该处需处理文本格式异常
                    try:
                        domain, ip = line.strip().split(':')
                    except ValueError:
                        print('ERROR: 读取配置文件错误，请检查配置文件格式！')
                        self.dns_dict = {}
                        time.sleep(1)
                        bias = 1
                        continue
                    self.dns_dict[domain] = ip
            if bias == 0:
                    break
            else:
                continue
        return len(self.dns_dict)

    def send_dns_request(self, domain):
        dns_query = dns.message.make_query(domain, "A")
        # 该try代码块用来捕捉超时 防止程序卡住
        try:
            response = dns.query.udp(dns_query, self.DNS_SERVER, port=self.DNS_PORT, timeout=2)
        except dns.exception.Timeout:
            print('dns请求超时')
            expected_ip = self.dns_dict[domain]
            return [False, domain, expected_ip, 'Timeout']
        # 该判断用来解决域名输入失误
        if not response.answer:
            expected_ip = self.dns_dict[domain]
            return [False, domain, expected_ip, 'None']
        for i in response.answer:
            try:
                result_ip = re.search(self.IP_RE_PA, i.to_text()).group()
                if result_ip == self.dns_dict[domain]:
                    # 解析正常逻辑
                    return [True, domain, result_ip]
                else:
                    # 解析异常逻辑
                    expected_ip = self.dns_dict[domain]
                    return [False, domain, expected_ip, result_ip]
            except AttributeError:
                continue

    def gen_log(self, request_info_list):
        if request_info_list[0]:
            self.logger.info("domain:{}, ip: {}, exceptional_ip: None, 域名解析正常".format(request_info_list[1],
                                                                                      request_info_list[2]))
        else:
            self.logger.error("domain:{}, ip: {}, exceptional_ip:{}, 域名解析异常".format(request_info_list[1],
                                                                                    request_info_list[2],
                                                                                    request_info_list[3]))

    def thread_worker(self, work_queue):
        while not work_queue.empty():
            try:
                domain = work_queue.get(block=False)
            except Empty:
                break
            else:
                res_list = self.send_dns_request(domain)
                self.gen_log(res_list)
                work_queue.task_done()

    def run(self):
        while True:
            # 读取txt信息 将映射存入字典
            len_of_dict = self.init_dict()

            # 核心代码 for循环
            if len_of_dict <= 100:
                print('轮询开始')
                for domain in self.dns_dict.keys():
                    # 将域名传入该方法 返回一个列表
                    print('正在执行send_request方法')
                    res_list = self.send_dns_request(domain)
                    # 将该列表传入该方法 写入日志
                    print('正在执行gen_log方法')
                    self.gen_log(res_list)
            # 核心代码 多线程入口
            else:
                thread_pool_size = int(len_of_dict/2)
                print('多线程开始 线程数%s' % thread_pool_size)
                if thread_pool_size >= 10: thread_pool_size = 10
                for domain in self.dns_dict.keys():
                    self.work_queue.put(domain)
                threads = [
                    Thread(target=self.thread_worker, args=(self.work_queue,))
                    for _ in range(thread_pool_size)
                ]
                for thread in threads:
                    thread.start()
                self.work_queue.join()
                while threads:
                    threads.pop().join()
            print('轮询结束')
            print(datetime.now())
            print(self.dns_dict)
            time.sleep(5)


if __name__ == '__main__':
    parser = optparse.OptionParser(
        '''
        e.x. python dns_test.py -t info.txt -s 192.168.1.2 -p 53
        -t <a text contain the map of the domains and ip>
        -s <proxy ip or dns server ip>
        -p <proxy port or dns server port>(optional)
        If you omit -p option, script will use default dns port is 53.
        '''
    )
    parser.add_option('-t', dest='text_name', type='string', help='specify mapping text file')
    parser.add_option('-ds', dest='dns_server_ip', type='string', help='specify proxy ip or dns server ip')
    parser.add_option('-dp', dest='dns_port', type='int', help='specify proxy port or dns server port')
    parser.add_option('-ss', dest='syslog_server_ip', type='string', help='specify syslog server ip')
    parser.add_option('-sp', dest='syslog_server_port', type='int', help='specify syslog server port')
    (options, args) = parser.parse_args()
    text_name = options.text_name
    dns_server_ip = options.dns_server_ip
    dns_port = options.dns_port
    syslog_ip = options.syslog_server_ip
    syslog_port = options.syslog_server_port
    if (text_name == None) | (dns_server_ip == None):
        print(parser.usage)
        exit(0)
    else:
        if dns_port == None:
            dns_port = 53
        if syslog_port == None:
            syslog_port = 514
    # text_name = 'test_data.txt'
    # dns_server_ip = '8.8.8.8'
    # dns_port = 53
    # syslog_ip = '192.168.3.37'
    # syslog_port = 514
    # 逻辑入口
    dns_sur = DNSSurveillance(text_name, dns_server_ip, dns_port, syslog_ip, syslog_port)
    dns_sur.run()
