# -*- coding:utf-8 -*-
import logging
import requests
import time

api_url = {
    "foreign": "https://api.dnspod.com",
    "domestic": "https://dnsapi.cn"
}

logger = logging.getLogger("dnspod")


class Dnspod(object):
    data = {
        'format': 'json',
        "lang": "cn",
        "error_on_empty": "no"
    }

    email = None
    password = None
    user_token = None
    domain = None
    domain_id = None
    record_id = None
    sub_domain = None
    foreign = False
    url = None
    current_ip = None

    def __init__(self, email, password, sub_domain, domain, foreign=False):
        self.email = email
        self.password = password
        self.sub_domain = sub_domain
        self.domain = domain
        self.foreign = foreign
        self.user_token = None
        self.url = None

        self._get_user_token()
        self.get_domain_id()
        self.get_record_id()
        if self.record_id is None:
            self.create_record()

    def _get_user_token(self):
        if self.foreign:
            self.url = api_url['foreign']
            param = self.data.copy()
            param.update({
                'login_email': self.email,
                'login_password': self.password,
            })
            resp = requests.post(self.url + '/Auth', data=param).json()
            self.user_token = resp.get('user_token')
        else:
            self.url = api_url['domestic']

    def get_domain_id(self):
        if self.domain_id is None:
            if self.foreign:
                self.data.update({'user_token': self.user_token})
            else:
                self.data.update({'login_email': self.email, 'login_password': self.password})
            try:
                resp = requests.post(self.url + '/Domain.List', data=self.data, timeout=10).json()
                domains = resp.get('domains')
                for d in domains:
                    name = d['name']
                    if self.domain == name:
                        self.domain_id = d['id']
                        break
            except Exception as e:
                logger.exception(e)

    def get_record_id(self):
        if self.record_id is None:
            self.data['domain_id'] = self.domain_id
            try:
                data = self.data.copy()
                data.update({"sub_domain": self.sub_domain})
                resp = requests.post(self.url + '/Record.List', data=data, timeout=10).json()
                records = resp.get('records')
                if len(records) > 1:
                    for r in records:
                        name = r['name']
                        if self.sub_domain == name:
                            self.remove_record(r['id'])
                else:
                    for r in records:
                        name = r['name']
                        if self.sub_domain == name:
                            self.record_id = r['id']
            except Exception as e:
                logger.exception(e)

    def remove_record(self, id):
        try:
            data = self.data.copy()
            data.update({"record_id": id})
            resp = requests.post(self.url + "/Record.Remove", data=data, timeout=10).json()
            now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            info = {"now": now, "message": resp['status']['message'], "resp": resp}
            logger.info(u"{now}删除记录结果:{message}, 接口返回{resp}".format(**info))
        except Exception as e:
            logging.exception(e)

    def upload_ip(self):
        self.data['record_id'] = self.record_id
        self.data['sub_domain'] = self.sub_domain
        if self.foreign:
            self.data['record_line'] = 'default'
        else:
            self.data['record_line'] = '默认'
        try:
            resp = requests.post(self.url + '/Record.Ddns', data=self.data).json()
            now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            info = {"now": now, "message": resp['status']['message'], "resp": resp}
            logger.info(u"{now}更新DNSPOD IP结果:{message}, 接口返回{resp}".format(**info))
            if str(resp['message']).equals('操作已经成功完成') == False:
                logging.info('修改dnspod不成功，开始重试3次')
                for i in range(0,3):
                    self.upload_ip(self)
        except Exception as e:
            logger.exception(e)

    def get_ip(self):
        ip_url = 'http://ip-api.com/json'
        try:
            resp = requests.get(ip_url)
            resp = resp.json()
            ip = resp.get('query', None)
            return ip
        except Exception as e:
            logger.exception(e)
        return None

    def create_record(self):
        ip = self.get_ip()
        if ip is not None:
            param = self.data.copy()
            param['sub_domain'] = self.sub_domain
            param['record_type'] = 'A'
            param['record_line'] = 'default' if self.foreign else '默认'
            param['value'] = ip
            param['ttl'] = 600
            try:
                resp = requests.post(self.url + '/Record.Create', data=param, timeout=10).json()
                status = resp['status']
                self.current_ip = ip
                if status['code'] == '1':
                    record = resp['record']
                    self.record_id = record['id']
                now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                info = {"now": now, "message": resp["status"]["message"], "resp": resp}
                logger.info(u"{now}添加DNSPOD子域名记录结果:{message}, 接口返回{resp}".format(**info))
            except Exception as e:
                logger.exception(e)
