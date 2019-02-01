#!/usr/bin/python3
# -*- coding:utf-8 -*-

import json
import logging
import sys
import time

import requests
import yaml
from QcloudApi.qcloudapi import QcloudApi

CONFIG_PATH = 'config.yml'
SECRET_ID = 'xxx'
SECRET_KEY = 'xxx'
CONFIG = {}

ipv4_flag = True
ipv6_flag = True

def main():
    record_list = get_config()
    record_ip_list = []

    for domain, sub_domain, record_type in record_list:
        record_id, current_ip = get_record_id(domain, sub_domain, record_type)
        if record_id is None:
            logging.error("No Sub Domain: %s" % sub_domain)
            continue

        record_ip_list.append({
            'domain': domain,
            'sub_domain': sub_domain,
            'type': record_type,
            'id': record_id,
            'old_ip': current_ip,
            'new_ip': current_ip
        })
        logging.info(F"{record_id} {sub_domain}.{domain}({current_ip})")
    while True:
        for item in record_ip_list:
            item['new_ip'] = get_ip(item['type'] == 'AAAA')
            if item['new_ip'] is None:
                logging.debug('sleep {} s'.format(CONFIG['sleep_time'] / 2))
                continue
            logging.debug("Current IP   : %s" % item['old_ip'])
            logging.debug("New IP       : %s" % item['new_ip'])

            logging.debug(item['old_ip'])
            logging.debug(item['new_ip'])
            logging.debug(item['old_ip'] != item['new_ip'])
            if item['old_ip'] != item['new_ip'] and change_ip(item):
                logging.info("[%s] ==> [%s]" %
                             (item['old_ip'], item['new_ip']))
                item['old_ip'] = item['new_ip']
        logging.debug('sleep {}s'.format(CONFIG['sleep_time']))
        time.sleep(CONFIG['sleep_time'])


def get_config():
    global SECRET_ID, SECRET_KEY, CONFIG
    stream = open(CONFIG_PATH, 'r')
    CONFIG = yaml.load(stream)
    SECRET_ID = CONFIG['secret_id']
    SECRET_KEY = CONFIG['secret_key']
    logging.info(CONFIG_PATH)
    logging.info('=' * 40)
    logging.info(F'secret_id: {SECRET_ID[:4]}xxxxxx{SECRET_ID[-4:]}')
    logging.info(F'secret_key: {SECRET_KEY[:4]}xxxxxx{SECRET_KEY[-4:]}')
    result = []
    for domain, items in CONFIG['domains'].items():
        for sub_domain, item in items.items():
            for record_type in item:
                logging.info(F'{sub_domain}.{domain}\t{record_type}')
                result.append((domain, sub_domain, record_type,))
    logging.info('=' * 40)
    return result


def get_record_id(domain, sub_domain, record_type):
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
        'domain': domain,
        'subDomain': sub_domain,
        'recordType': record_type,
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


def get_ip(ipv6=False):
    global ipv4_flag, ipv6_flag
    ip = None
    try:
        http = requests.Session()
        if ipv6:
            result = http.get("https://api-ipv6.ip.sb/ip")
            if not ipv6_flag:
                logging.info("ipv6 is ok!")
                ipv6_flag = True
        else:
            result = http.get("https://api-ipv4.ip.sb/ip")
            if not ipv4_flag:
                logging.info("ipv4 is ok!")
                ipv4_flag = True
        ip = result.text.strip()
    except Exception:
        import traceback
        logging.error(traceback.format_exc())
        if ipv6 and not ipv6_flag:
            logging.warning("ipv6 error!")
            ipv6_flag = False
        elif not ipv6 and not ipv4_flag:
            logging.warning("ipv4 error!")
            ipv4_flag = False
    return ip


def change_ip(record_obj):
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
        'domain': record_obj['domain'],
        'recordId': record_obj['id'],
        'subDomain': record_obj['sub_domain'],
        'recordType': record_obj['type'],
        'recordLine': '默认',
        'value': record_obj['new_ip']
    }

    try:
        service = QcloudApi(module, config)
        logging.debug("Get Query URL: %s" %
                      service.generateUrl(action, action_params))
        result = service.call(action, action_params)
        result = str(result, encoding='utf-8')
        result = json.loads(result)
        logging.debug(result)
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
    formatter = '%(asctime)s %(levelname)-8s %(filename)s:%(lineno)d\t%(threadName)-10s: %(message)s'
    logging.basicConfig(level=logging.INFO,
                        filename='qcloud-ddns.log',
                        format=formatter)
    log = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(formatter))
    log.addHandler(handler)

    main()
