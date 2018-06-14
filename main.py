#!/usr/bin/python3
# -*- coding:utf-8 -*-

import json
import socket
import time
import logging

from QcloudApi.qcloudapi import QcloudApi

SECRET_ID = 'xxx'
SECRET_KEY = 'xxx'
DOMAIN = 'xxx'
SUB_DOMAIN = 'xxx'

def main():
    logging.basicConfig(level=logging.INFO,
                        filename='ddns_log.log',
                        format='%(asctime)s %(levelname)-8s %(filename)s:%(lineno)d\t'
                        '%(threadName)-10s: %(message)s')
    logging.info("Domain       : %s" % DOMAIN)
    logging.info("Sub domain   : %s" % SUB_DOMAIN)
    sub_domain = SUB_DOMAIN
    record_id, current_ip = get_record_id(sub_domain)
    if record_id is None:
        # print("No SubDomain: %s" % sub_domain)
        logging.error("No Sub Domain: %s" % sub_domain)
        return
    # print("record_id : %s" % record_id)
    logging.info("Get record id: %s" % record_id)
    while True:
        ip = get_ip()
        ip = str(ip, encoding='utf-8')
        # print("current_ip: %s\nnew_ip    : %s" % (current_ip, ip))
        logging.debug("Current IP   : %s" % current_ip)
        logging.debug("New IP       : %s" % ip)

        if current_ip != ip and change_ip(ip, record_id, sub_domain):
            logging.info("Change IP Successed! [%s] ==> [%s]" % (current_ip, ip))
            current_ip = ip
        time.sleep(30)


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

    try:
        service = QcloudApi(module, config)
        # print(service.generateUrl(action, action_params))
        logging.debug("Get Query URL: %s" % service.generateUrl(action, action_params))
        result = service.call(action, action_params)
        result = str(result, encoding='utf-8')
        result = json.loads(result)
        if len(result['data']['records']) != 1:
            return None
        return result['data']['records'][0]['id'], result['data']['records'][0]['value']
        
    except Exception :
        import traceback
        print(traceback.format_exc())

def get_ip():
    sock = socket.create_connection(('ns1.dnspod.net', 6666), 20)
    ip = sock.recv(16)
    sock.close()
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
        # print(service.generateUrl(action, action_params))
        logging.debug("Get Query URL: %s" % service.generateUrl(action, action_params))
        result = service.call(action, action_params)
        result = str(result, encoding='utf-8')
        result = json.loads(result)
        if result['code'] != 0:
            # print('Error! code:%s\n\t%s' % (result['code'], result['message']))
            logging.error("Code   : %s" % result['code'])
            logging.error("Message: %s" % result['message'])
            return False
        else:
            # print(result['data'])
            logging.debug("Record id    : %s" % result['data']['record']['id'])
            logging.debug("Record status: %s" % result['data']['record']['status'])
            logging.debug("Record value : %s" % result['data']['record']['value'])
            logging.debug("Record name  : %s" % result['data']['record']['name'])
            logging.debug("Record weight: %s" % result['data']['record']['weight'])
            return True
        
    except Exception :
        import traceback
        print(traceback.format_exc())

if __name__ == '__main__':
    main()
