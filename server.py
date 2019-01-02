# -*- coding:utf-8 -*-
import logging
import time

import requests

try:
    import ConfigParser
except:
    import configparser as ConfigParser
from dnspod import Dnspod

# 获取自己的公网ip
get_ip_url = 'http://xxxx.com:88/raid-monitor/cgi/ddns/getRemoteIp'
# 更新自己的ip
report_ip_url = 'http://xxxx.com:88/raid-monitor/cgi/ddns/setIp'
# 获取本服务器server_code
server_code_url = 'http://127.0.0.1:88/node/api/business/getServerCode'
cnf_path = '/opt/server_init/dnspod_cnf.ini'
log_path = 'dnspod.log'
foreign = 'N'

logger = logging.getLogger("dnspod")


# 根据dnspod_cnf.ini读取配置信息
def get_config():
    config = ConfigParser.ConfigParser()
    config.readfp(open(cnf_path), 'rb')
    email = config.get("global", "login_email")
    password = config.get("global", "login_password")
    domain = config.get("global", "domain")
    sub_domain = config.get("global", "sub_domain")
    server_code = get_subdomain()
    sub_domain = server_code if server_code else sub_domain
    is_forigin = foreign == 'Y'
    dns = Dnspod(email, password, sub_domain, domain, is_forigin)
    return dns, sub_domain


# 获取server_code
def get_subdomain():
    try:
        resp = requests.get(server_code_url, timeout=5).json()
        info = {"resp": resp}
        logger.info("从接口中获取的serverCode,{resp}".format(**info))
        return resp["serverCode"]
    except Exception as e:
        logger.exception(e)
        return None

# 获取自己的公网ip
def get_ip():
    try:
        now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        resp = requests.get(get_ip_url, timeout=5).json()
        ip = resp['object']
        info = {"now": now, "ip": ip}
        logger.info(u'{now}从接口中获取到ip：{ip}'.format(**info))
        return ip
    except Exception as e:
        logger.exception(e)
        return None

# 向raid-monitor上报ip
def report(ip, nodeCode):
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    data = {"ip": ip, "serverCode": nodeCode}
    try:
        requests.post(report_ip_url, data=data)
        info = {"now": now, "ip": ip}
        logger.info(u"{now}上报到ip到平台：{ip}".format(**info))
    except Exception as e:
        logger.exception(e)


def run(ip, node_code):
    try:
        report(ip, node_code)
    except Exception as e:
        logger.exception(e)


def main():
    logger.setLevel(logging.INFO)
    hander = logging.FileHandler(log_path, encoding='utf-8')
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s", "%Y-%m-%d %H:%M:%S")
    hander.setFormatter(formatter)
    logger.addHandler(hander)
    current_ip = None
    dnspod, node_code = get_config()

    while True:
        ip = get_ip()
        # ip发生变化才通知dnspod修改记录
        if ip and ip != current_ip:
            run(ip, node_code)
            dnspod.upload_ip()
            current_ip = ip
        time.sleep(60)


if __name__ == '__main__':
    main()
