# coding=utf-8
import base64
import gzip
import hashlib
import hmac
import operator
import random
import re
import time

import dns.resolver
import requests

SecretId = "AKIDE2i9KEDOaZCxRyx5qKfdOtBEH3aqlb3L"
SecretKey = "dwKaAAwpU8eDhuue6"
ServerURL = "https://cns.api.qcloud.com/v2/index.php"

random.seed(time.time())


def sha1(path):
    with open(path, "rb") as f:
        return hashlib.sha1(f.read()).hexdigest()


def sign(dictionary):
    """腾讯云API签名"""
    sorted_dict = sorted(dictionary.items(), key=operator.itemgetter(0), reverse=False)
    option_list = []
    for k, v in sorted_dict:
        option_list.append(k + "=" + str(v))
    req_string = '&'.join(option_list)
    raw_string = "GETcns.api.qcloud.com/v2/index.php?" + req_string
    # print(raw_string)
    signature = base64.b64encode(
        hmac.new(
            SecretKey.encode('utf-8'),
            raw_string.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()
    ).decode('utf-8')
    # print(signature)
    return signature


def add_dns_record(text, subDomain, recordType):
    while True:
        domain_options = {
            'Timestamp': int(time.time()),
            'Nonce': random.randint(1, 999999999),
            'SecretId': SecretId,
            'SignatureMethod': 'HmacSHA256',
            'Action': 'RecordCreate',
            'domain': 'gcc.ac.cn',
            'subDomain': subDomain,
            'recordType': recordType,
            'recordLine': '默认',
            'value': text
        }
        domain_options["Signature"] = sign(domain_options)
        r = requests.get(ServerURL, params=domain_options)
        print(r.json())
        if r.json()['code'] == 0 or r.json()['code'] == 4000:
            break


def get_dns_record(subDomain='', recordType=''):
    domain_options = {
        'Timestamp': int(time.time()),
        'Nonce': random.randint(1, 999999999),
        'SecretId': SecretId,
        'SignatureMethod': 'HmacSHA256',
        'Action': 'RecordList',
        'domain': 'gcc.ac.cn',
        'subDomain': subDomain,
        'recordType': recordType
    }
    domain_options["Signature"] = sign(domain_options)
    r = requests.get(ServerURL, params=domain_options)
    # print(json.dumps(r.json(), indent=4))
    return r.json()


def del_dns_record(recordId):
    domain_options = {
        'Timestamp': int(time.time()),
        'Nonce': random.randint(1, 999999999),
        'SecretId': SecretId,
        'SignatureMethod': 'HmacSHA256',
        'Action': 'RecordDelete',
        'domain': 'gcc.ac.cn',
        'recordId': recordId
    }
    domain_options["Signature"] = sign(domain_options)
    r = requests.get(ServerURL, params=domain_options)
    print(r.json())


def encode_file(path, enable_gzip=False):
    with open(path, 'rb') as f:
        raw_data = f.read()
    print("编码前大小：", len(raw_data))
    if enable_gzip:
        raw_data = gzip.compress(raw_data)
        print("压缩后大小：", len(raw_data))
    b64_string = base64.b64encode(raw_data)
    print("编码后大小：", len(b64_string))
    # print(b64_string.decode())
    return b64_string.decode()


def decode_file(base64txt, path, enable_gzip=False):
    # print(base64txt)
    print("解码前大小：", len(base64txt))
    raw_data = base64.b64decode(base64txt)
    print("解码后大小：", len(raw_data))
    if enable_gzip:
        raw_data = gzip.decompress(raw_data)
    # print(raw_data)
    with open(path, "wb") as f:
        f.write(raw_data)


def add_file(path, subDomain):
    base64txt = encode_file(path)
    txt_list = re.findall(r'.{255}', base64txt)
    txt_list.append(base64txt[len(txt_list) * 255:])
    for a in range(0, len(txt_list)):
        print(txt_list[a])
        add_dns_record(txt_list[a], "%d.%s" % (a, subDomain), 'TXT')
        if (a + 1) % 25 == 0:
            time.sleep(5)  # 休息一下防止超出配额限制


def del_file(subDomain):
    for a in range(0, 10000):
        id_list = get_dns_record(subDomain="%d.%s" % (a, subDomain), recordType='TXT')['data']['records']
        if id_list:
            print("删除：", a)
            del_dns_record(id_list[0]['id'])
        else:
            break
        if (a + 1) % 25 == 0:
            time.sleep(5)  # 休息一下防止超出配额限制


def get_file(subDomain, path):
    base64txt = ''
    for a in range(0, 10000):
        try:
            answers = dns.resolver.query('%d.%s.gcc.ac.cn' % (a, subDomain), 'TXT')
            for rdata in answers:
                print(str(rdata))
                base64txt += str(rdata)[1:-1]
        except dns.resolver.NoAnswer:
            break
        except dns.resolver.NXDOMAIN:
            break
    decode_file(base64txt, path)


if __name__ == '__main__':
    """测试代码"""
    # encode_file('1.docx', enable_gzip=True)
    # src_hash = sha1('1.docx')
    # add_file('1.docx', 'file')
    # time.sleep(5)
    get_file('file', 'test.docx')
    # new_hash = sha1('test.docx')
    # if src_hash != new_hash:
    #     print("前后hash不一致！")
    # else:
    #     print("前后hash一致")
    # del_file('file')
    # add_dns_record('啊啊啊啊啊', "test", "TXT")
    # time.sleep(5)
    # answers = dns.resolver.query("test.gcc.ac.cn", 'TXT')
    # for answer in answers:
    #     print(str(answer)[4:-1].encode("ISO-8859-1").decode("punycode"))
