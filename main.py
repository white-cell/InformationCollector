#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#信息收集扫描框架
#

import lib.requests as requests
from lib.termcolor import colored
from bs4 import BeautifulSoup
import threading
import Queue
import time
import sys
import json
import re
import os
import logging
import random
import base64

reload(sys)
sys.setdefaultencoding('utf-8')
requests.packages.urllib3.disable_warnings()
THREAD_COUNT=20
TIME_OUT=10
USER_AGENTS=[
    'Mozilla/4.0 (compatible; MSIE 5.0; SunOS 5.10 sun4u; X11)',
    'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Avant Browser;',
    'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1)',
    'Microsoft Internet Explorer/4.0b1 (Windows 95)',
    'Opera/8.00 (Windows NT 5.1; U; en)',
    'Mozilla/4.0 (compatible; MSIE 5.0; AOL 4.0; Windows 95; c_athome)',
    'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
    'Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.5 (like Gecko) (Kubuntu)',
    'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; ZoomSpider.net bot; .NET CLR 1.1.4322)',
    'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; QihooBot 1.0 qihoobot@qihoo.net)']
#MY_PROXY = { "http":"127.0.0.1:8888","https":"127.0.0.1:8888"}
MY_PROXY = {}
bing_api = "http://www.bing.com/search?q=site%3A"
baidu_api = "http://www.baidu.com/s?wd=site%3A"
ping_api = "https://ping.aizhan.com/api/ping?callback=flightHandler"
censys_api_id = ""
censys_api_secret = ""

domain_queue = Queue.Queue()
Lock = threading.Lock()
result_list = []
Sourceip = []
domains = []

#主程序
class Collector(threading.Thread):
    def __init__(self,s):
        threading.Thread.__init__(self)
        self.domain_queue = domain_queue
        self.s = s
    def run(self):
        while not self.domain_queue.empty():
            host = self.domain_queue.get()
            output('Starting scan target : %s'%host, 'green')
            self.save_report(host,self.getTitle(host),self.getRealIp(host),self.getSearch(host))
            output('Complete scan target : %s'%host, 'green')
    def getSearch(self,host):
        returns = []
        try:
            resp1 = requests.get(bing_api+host,timeout=TIME_OUT, allow_redirects=True)
            resp2 = requests.get(baidu_api+host,timeout=TIME_OUT)
        except Exception,e:
            logging.error(e)
            return returns
        if resp1.status_code == 200:
            results = re.findall('<h2><a target="_blank" href="(.*?)" h="ID=.*?">(.*?)</a></h2>',resp1.text)
            if results:
                for result in results:
                    returns.append("Bing| %s| <a href=\"%s\" target=\"_blank\">%s</a></br>"%(result[1],result[0],result[0][:100]))
        if resp2.status_code == 200:
            results = re.findall('none;">(.*?)&nbsp;</a>.*?{"title":"(.*?)","url":"(.*?)"}',resp2.text)
            if results:
                for result in results:
                    resp = requests.get(result[2],timeout=TIME_OUT, allow_redirects=False)
                    returns.append("BaiDu|%s|<a href=\"%s\" target=\"_blank\">%s</a></br>"%(result[1],resp.headers['Location'],resp.headers['Location']))
        return returns
    def getTitle(self,host):
        if not host.startswith('http'):
            host = "http://"+host
        try:
            resp = requests.get(host,timeout=TIME_OUT, headers={"User-Agent": random.choice(USER_AGENTS)}, allow_redirects=True, proxies=MY_PROXY)
        except Exception,e:
            logging.error(e)
            host = host.replace("http","https")
            try:
                resp = requests.get(host,timeout=TIME_OUT, headers={"User-Agent": random.choice(USER_AGENTS)}, allow_redirects=True, verify=False, proxies=MY_PROXY)
            except Exception,e:
                logging.error(e)
                return "del~"

        try:
            resp.encoding = requests.utils.get_encodings_from_content(resp.content)[0]
        except:
            resp.encoding = 'utf-8'
        soup = BeautifulSoup(resp.content, "html.parser")
        try:
            title = soup.title.string
        except Exception,e:
            #print e
            title = '获取失败'
        if 'Server' in resp.headers:
            title = title+'<td>'+resp.headers['server']+'</td>'
        else :
            title = title+'<td></td>'
        return title
    def getRealIp(self,host):
        cookies={}
        for line in ping_Cookie.split(';'):
            if '=' in line:
                name,value=line.strip().split('=',1)
                cookies[name]=value
        try:
            with Lock:
                data = {"type":"ping","domain":host,"_csrf":ping_csrf}
                resp = self.s.post(ping_api, data=data, cookies=cookies, timeout=10, proxies=MY_PROXY)
        except:
            try:
                with Lock:
                    data = {"type":"http","domain":host,"_csrf":ping_csrf}
                    resp = self.s.post(ping_api, data=data, cookies=cookies, timeout=10, proxies=MY_PROXY)
            except Exception,e:
                logging.error("[*]%s %s"%(host,e))
                return
        if resp.status_code == 200:
            ip_list = re.findall('"ip":"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"',resp.text)
            if ip_list:
                new_ips = []
                for ip in ip_list:
                    if ip not in new_ips:
                        new_ips.append(ip)
                ip_list = new_ips
                if len(ip_list)==1:
                    Sourceip.append(ip_list)
                    return "<a href='https://censys.io/ipv4/%s'>%s</a>"%(ip_list[0],ip_list[0])
                elif len(ip_list)>=2:
                    return '</br>'.join(ip_list)
        return 'api fail'
    def save_report(self,host,title,ip,search_result):
        if search_result:
            if title == 'del~':
                result_list.append("<tr><td>%s</td><td></td><td></td><td>%s</td><td></td></tr>"%(host,ip))
                for result in search_result:
                    result_list.append(result.encode("utf-8"))
                result_list.append("</td></tr>")
            else:
                result_list.append(("<tr><td><a href=\"http://%s\">%s</a></td><td>%s</td><td>%s</td><td>"%(host,host,title,ip)).encode("utf-8"))
                for result in search_result:
                    result_list.append(result.encode("utf-8"))
                result_list.append("</td></tr>")
        else:
            result_list.append(("<tr><td><a href=\"http://%s\">%s</a></td><td>%s</td><td>%s</td><td>"%(host, host, title, ip)).encode("utf-8"))
            result_list.append("</td></tr>")

#标准化输出
def output(info, color='white'):
    with Lock:
        print colored("[%s] %s"%(time.strftime('%H:%M:%S',time.localtime(time.time())), info),color)
#生成报告
def save_report():
    with open("./reports/%s_result.html"%time.strftime("%Y-%m-%d,%H-%M-%S", time.localtime()),'a') as report:
        report.write("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\"><html xmlns=\"http://www.w3.org/1999/xhtml\"><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"><title>信息收集报告</title><style>body {width:auto; margin:auto; margin-top:10px; background:rgb(200,200,200);}p {color: #666;}th {color:#002E8C; font-size: 1em; padding-top:5px;}</style></head><body><table border=\"1\"><tr><th>Target</th><th>Title</th><th>Server</th><th>SourceIp</th><th>SpiderUrl</th></tr>")
        for result in result_list:
            report.write(result)
        report.write("</table></body></html>")

def search_cert_from_crt(target):
    output("Start search_cert_from_crt",'green')
    crt_api = "https://crt.sh/?q=%"
    cert_result = []
    try:
        resp = requests.get(crt_api+target, timeout=10,proxies=MY_PROXY)
    except Exception,e:
        output("search_cert_from_crt connect error",'red')
        return []
    id_result = re.findall("href=\"\?id=(.*?)\"",resp.text)
    for i in id_result:
        try:
            resp = requests.get("https://crt.sh/?id="+i, timeout=10,proxies=MY_PROXY)
            result = re.findall("\"//censys.io/certificates/(.*?)\"",resp.text)
            cert_result.append(result[0])
        except Exception,e:
            logging.error(e)
            continue
    cert_result = list(set(cert_result))
    output("Complete search_cert_from_crt",'green')
    return cert_result

def search_subdomain_from_virustotal(target):
    output("Start search_cert_from_crt",'green')
    domain_result = []
    url = "https://www.virustotal.com/ui/domains/"+target+"/subdomains?limit=30"
    try:
        resp = requests.get(url, timeout=10, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENTS)})
        result = json.loads(resp.text)
    except Exception,e:
        output("search_subdomain_from_virustotal connect error",'red')
        return []
    while result["links"].has_key("next"):
        try:
            resp = requests.get(result["links"]["next"], timeout=10, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENTS)})
            result = json.loads(resp.text)
            for i in xrange(len(result["data"])):
                domain_result.append(result["data"][i]["id"])
            time.sleep(1)
        except Exception,e:
            logging.error(e)
            continue
    output("Complete search_cert_from_crt",'green')
    return domain_result

def search_subdomain_from_threatcrowd(target):
    output("Start search_subdomain_from_threatcrowd",'green')
    try:
        url = "https://www.threatcrowd.org/domain.php?domain="+target
        resp = requests.get(url, timeout=10, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENTS)})
        domain_result = re.findall("'>([^>]*?\."+target+")</a>",resp.text)
        output("Complete search_subdomain_from_threatcrowd",'green')
        return domain_result
    except Exception,e:
        output("search_subdomain_from_threatcrowd connect error",'red')
        return []
def search_subdomain_from_findsubdomain(target):
    output("Start search_subdomain_from_findsubdomain",'green')
    try:
        url = "https://findsubdomains.com/subdomains-of/"+target
        resp = requests.get(url, timeout=10, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENTS)})
        domain_result = re.findall("'([^<>\"/]*?\."+target+")",resp.text)
        output("Complete search_subdomain_from_findsubdomain",'green')
        return domain_result
    except Exception,e:
        output("search_subdomain_from_findsubdomain connect error",'red')
        return []

def search_ip_from_censys(target, cert_list):
    output("Start search_ip_from_censys",'green')
    ip_result = []
    p = 1
    ps = 2
    for i in cert_list:
        while p <= ps:
            try:
                resp = requests.post("https://censys.io/api/v1/search/ipv4",data='{"query":"'+i+'","page":'+str(p)+',"fields":["ip"],"flatten":true}', auth=(censys_api_id, censys_api_secret), timeout=10, proxies=MY_PROXY)
                result1 = json.loads(resp.text)
                p += 1
                ps = result1["metadata"]["pages"]
                for i in xrange(100):
                    ip_result.append(result1["results"][i]['ip'])
            except Exception,e:
                logging.error(e)
                p += 1
                continue
    ip_result = list(set(ip_result))
    output("Complete search_ip_from_censys",'green')
    return ip_result

#初始化
def init():
    logging.basicConfig(level=logging.WARNING,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s <%(message)s>',
                    filename='run.log',
                    filemode='w')
    print colored("""
 ___          __                                 _    _
|_ _| _ __   / _|  ___   _ __  _ __ ___    __ _ | |_ (_)  ___   _ __
 | | | '_ \ | |_  / _ \ | '__|| '_ ` _ \  / _` || __|| | / _ \ | '_ \   __author__="Jaqen"
 | | | | | ||  _|| (_) || |   | | | | | || (_| || |_ | || (_) || | | |
|___||_| |_||_|   \___/ |_|   |_| |_| |_| \__,_| \__||_| \___/ |_| |_|

  ____         _  _              _
 / ___|  ___  | || |  ___   ___ | |_   ___   _ __
| |     / _ \ | || | / _ \ / __|| __| / _ \ | '__|
| |___ | (_) || || ||  __/| (__ | |_ | (_) || |
 \____| \___/ |_||_| \___| \___| \__| \___/ |_|
""",'yellow')
    threads = []
    if len(sys.argv) == 3:
        global ping_Cookie
        global ping_csrf
        global domains
        print '\n[*] starting at %s\n'%time.strftime('%H:%M:%S',time.localtime(time.time()))
        if sys.argv[1] == '-f':
            if str(sys.argv[2]).endswith('.txt'):
                with open(sys.argv[2],'r') as list:
                    for domain in list.readlines():
                        domain = domain.rstrip('\n')
                        domain_queue.put(domain.rstrip('\r'))
            else:
                usage()
                sys.exit()
        if sys.argv[1] == '-i':
            ip = []
            target = sys.argv[2]
            #子域名收集
            cert_list = search_cert_from_crt(target)
            domains.extend(search_subdomain_from_virustotal(target))
            domains.extend(search_subdomain_from_threatcrowd(target))
            domains.extend(search_subdomain_from_findsubdomain(target))
            domains = set(domains)
            with open("./history/%s-domains.txt"%target,'w') as domains_output:
                for i in domains:
                    domain_queue.put(i)
                    domains_output.write(i+'\n')
            #通过证书收集源ip
            if censys_api_id and censys_api_secret:
                ip.extend(search_ip_from_censys(target, cert_list))
                for i in ip:
                    Sourceip.append(i)
            else:
                output("未配置censys_api_id和censys_api_secret，无法使用censys。",'red')
        resp = requests.get("https://ping.aizhan.com/", timeout=TIME_OUT, headers={"User-Agent": random.choice(USER_AGENTS)}, proxies=MY_PROXY)
        ping_Cookie = resp.headers['Set-Cookie']
        csrf = re.findall('"csrf-token" content="(.*?)"',resp.text[250:450])
        ping_csrf = csrf[0]
        s = requests.Session()
        scan_threads=[Collector(s)for i in xrange(THREAD_COUNT)]
        threads.extend(scan_threads)
        [thread.start() for thread in threads]
        [thread.join() for thread in threads]
        save_report()
        if sys.argv[1] == '-i':
            print '[+] Sourceip'
            with open("./history/%s-Sourceip.txt"%target,'w') as Sourceip_output:
                for i in Sourceip:
                    Sourceip_output.write(i[0]+'\n')
                    print i[0]
        else:
            print '[+] Sourceip'
            for i in Sourceip:
                print i[0]
        print '\n[*] shutting down at %s\n'%time.strftime('%H:%M:%S',time.localtime(time.time()))
    else:
        usage()

def usage():
    print "Usage: python "+sys.argv[0]+" -i baidu.com \n       python "+sys.argv[0]+" -f host.txt\n"


if __name__ == '__main__':
    init()
