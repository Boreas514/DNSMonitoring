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


class DNSSurveillance(object):
    def __init__(self, text_name, server, port):
        self.dns_dict = dns_dict
        self.text_name = text_name
        self.DNS_SERVER = server
        self.DNS_PORT = port
        self.IP_RE_PA = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        self.SYSLOG_SERVER = '192.168.3.37'
        self.SYSLOG_PORT = 514

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
        with open(self.text_name, 'r') as standard_file:
            for line in standard_file:
                line.replace('：', ':')
                domain, ip = line.strip().split(':')
                self.dns_dict[domain] = ip
        return len(self.dns_dict)

    def send_dns_request(self, domain):
        dns_query = dns.message.make_query(domain, "A")
        response = dns.query.udp(dns_query, self.DNS_SERVER, port=self.DNS_PORT)
        for i in response.answer:
            try:
                result_ip = re.search(self.IP_RE_PA, i.to_text())
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
            self.logger.info("domain:{}, ip: {}, exceptional_ip: None, 域名解析正常".format(request_info_list[1], request_info_list[2]))
        else:
            self.logger.error("domain:{}, ip: {}, exceptional_ip:{}, 域名解析异常".format(request_info_list[1], request_info_list[2], request_info_list[3]))


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
            # 清空dns字典
            self.dns_dict = {}
            # 读取txt信息 将映射存入字典
            len_of_dict = self.init_dict()

            # 核心代码 for循环
            if len_of_dict <= 100:
                for domain in self.dns_dict.keys():
                    # 将域名传入该方法 返回一个列表
                    res_list = self.send_dns_request(domain)
                    # 将该列表传入该方法 写入日志
                    self.gen_log(res_list)
            # 核心代码 多线程入口
            else:
                thread_pool_size = int(len_of_dict/70)
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
            time.sleep(2)


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
    parser.add_option('-s', dest='server_ip', type='string', help='specify proxy ip or dns server ip')
    parser.add_option('-p', dest='port', type='int', help='specify proxy port or dns server port')
    (options, args) = parser.parse_args()
    text_name = options.text_name
    server_ip = options.server_ip
    port = options.port
    if (text_name == None) | (server_ip == None):
        print parser.usage
        exit(0)
    else:
        if port == None:
            port = 53
    # 逻辑入口
    dns_sur = DNSSurveillance(text_name, server_ip, port)
    dns_sur.run()
