#!/usr/bin/python3
# -*- coding:utf-8 -*-

import json
import logging
import socket
import sys
import time

import yaml
from QcloudApi.qcloudapi import QcloudApi

CONFIG_PATH = 'config.yml'
SECRET_ID = 'xxx'
SECRET_KEY = 'xxx'
DOMAIN = 'xxx'
SUB_DOMAIN = 'xxx'

network_flag = True

def main():
    formatter = '%(asctime)s %(levelname)-8s %(filename)s:%(lineno)d\t%(threadName)-10s: %(message)s'
    logging.basicConfig(level=logging.INFO,
                        filename='qcloud-ddns.log',
                        format=formatter)
    log = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(formatter))
    log.addHandler(handler)

    get_config()
    logging.info("Domain       : %s" % DOMAIN)
    logging.info("Sub domain   : %s" % SUB_DOMAIN)
    sub_domain = SUB_DOMAIN
    record_id, current_ip = get_record_id(sub_domain)
    if record_id is None:
        logging.error("No Sub Domain: %s" % sub_domain)
        return
    logging.info("Get record id: %s" % record_id)
    while True:
        ip = get_ip()
        if ip is None:
            time.sleep(10)
            continue
        ip = str(ip, encoding='utf-8')
        logging.debug("Current IP   : %s" % current_ip)
        logging.debug("New IP       : %s" % ip)

        if current_ip != ip and change_ip(ip, record_id, sub_domain):
            logging.info(
                "Change IP Successed! [%s] ==> [%s]" % (current_ip, ip))
            current_ip = ip
        time.sleep(30)


def get_config():
    global SECRET_ID, SECRET_KEY, DOMAIN, SUB_DOMAIN
    stream = open(CONFIG_PATH, 'r')
    config = yaml.load(stream)
    SECRET_ID = config['secret_id']
    if SECRET_ID == 'your_secret_id':
        logging.error("Config error!")
        exit(-1)
    SECRET_KEY = config['secret_key']
    DOMAIN = list(config['domain'].keys())[0]
    SUB_DOMAIN = config['domain'][DOMAIN][0]


def get_record_id(sub_domain):
    module = 'cns'
    action = 'RecordList'
    config = {
        'Region': 'ap-beijing',
        'secretId': SECRET_ID,
        'secretKey': SECRET_KEY,
        'method': 'GET',
        'SignatureMethod': 'HmacSHA256'
    }
    action_params = {
        'domain': DOMAIN,
        'subDomain': sub_domain,
        'recordType': 'A',
    }
    result = None
    try:
        service = QcloudApi(module, config)
        logging.debug("Get Query URL: %s" %
                      service.generateUrl(action, action_params))
        result = service.call(action, action_params)
        result = str(result, encoding='utf-8')
        result = json.loads(result)
    except Exception:
        import traceback
        logging.error(traceback.format_exc())

    if result is None or len(result['data']['records']) != 1:
        return None, None
    return result['data']['records'][0]['id'], result['data']['records'][0]['value']

def get_ip():
    global network_flag
    ip = None
    try:
        sock = socket.create_connection(('ns1.dnspod.net', 6666), 20)
        ip = sock.recv(16)
        sock.close()
        if not network_flag:
            logging.info("network is ok!")
            network_flag = True
    except Exception:
        if network_flag:
            logging.warning("network error!")
            network_flag = False
    return ip


def change_ip(ip, record_id, sub_domain):
    module = 'cns'
    action = 'RecordModify'
    config = {
        'Region': 'ap-beijing',
        'secretId': SECRET_ID,
        'secretKey': SECRET_KEY,
        'method': 'GET',
        'SignatureMethod': 'HmacSHA256'
    }
    action_params = {
        'domain': DOMAIN,
        'recordId': record_id,
        'subDomain': sub_domain,
        'recordType': 'A',
        'recordLine': '默认',
        'value': ip
    }

    try:
        service = QcloudApi(module, config)
        logging.debug("Get Query URL: %s" %
                      service.generateUrl(action, action_params))
        result = service.call(action, action_params)
        result = str(result, encoding='utf-8')
        result = json.loads(result)
        if result['code'] != 0:
            logging.error("Code   : %s" % result['code'])
            logging.error("Message: %s" % result['message'])
            return False
        else:
            logging.debug("Record id    : %s" % result['data']['record']['id'])
            logging.debug("Record status: %s" %
                          result['data']['record']['status'])
            logging.debug("Record value : %s" %
                          result['data']['record']['value'])
            logging.debug("Record name  : %s" %
                          result['data']['record']['name'])
            logging.debug("Record weight: %s" %
                          result['data']['record']['weight'])
            return True
    except Exception:
        import traceback
        logging.error(traceback.format_exc())
    return False


if __name__ == '__main__':
    main()

