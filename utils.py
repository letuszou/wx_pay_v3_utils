# coding=utf-8

import json
import time

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import random
import string
import base64
from django.db import models


#
#
#  注意 当前环境 python2.7
#
#
def pay_v3_key_task():
    # 定时任务  定时刷新微信获取的证书
    str_data = PayV3Utils().get_pay_v3_certificates()
    json_data = json.loads(str_data)
    data = json_data['data'][0]

    effective_time = data['effective_time']
    expire_time = data['expire_time']
    serial_no = data['serial_no']

    encrypt_certificate = data['encrypt_certificate']
    algorithm = encrypt_certificate['algorithm']
    associated_data = encrypt_certificate['associated_data']
    ciphertext = encrypt_certificate['ciphertext']
    nonce = encrypt_certificate['nonce']
    open_key = PayV3OpenKey.objects.create()
    open_key.effective_time = effective_time
    open_key.expire_time = expire_time
    open_key.serial_no = serial_no
    open_key.algorithm = algorithm
    open_key.associated_data = associated_data
    open_key.ciphertext = ciphertext
    open_key.nonce = nonce
    open_key.save()


class PayV3OpenKey(models.Model):
    """建立存储 key的数据库 注意 只有一条数据就可以了  也可以用缓存 """

    id = models.CharField(u'ID', primary_key=True, max_length=30, blank=True)
    serial_no = models.CharField(u'serial_no', max_length=64, default='')

    effective_time = models.CharField(u'effective_time', max_length=64, default='')
    expire_time = models.CharField(u'expire_time', max_length=64, default='')

    algorithm = models.CharField(u'algorithm', max_length=64, default='')
    associated_data = models.CharField(u'associated_data', max_length=64, default='')
    ciphertext = models.TextField(u'ciphertext', default='')
    nonce = models.CharField(u'nonce', max_length=64, default='')

    def save(self, *args, **kwargs):
        super(PayV3OpenKey, self).save(*args, **kwargs)
        return self

    class Meta:
        db_table = 'pay_v3_open_key'
        verbose_name = '微信支付V3 的公钥'
        ordering = ['-create_time']


class WxPayConf_OPEN_LJ(object):
    # 用于存储微信支付网页 后台相关的信息

    APPID = ''
    APPSECRET = ''
    MCHID = ''

    KEY = ''
    API_V3_KEY = ''
    # 这个序列号和证书应该区分通过定时任务获取的
    serial_No = ''
    SSLCERT_PATH = ''
    SSLKEY_PATH = ''


class PayV3Utils(object):
    """微信支付 API V3 工具类"""

    def __init__(self, pay3_conf=WxPayConf_OPEN_LJ()):
        self.path = 'https://api.mch.weixin.qq.com'
        self.pay3_conf = pay3_conf
        self.nonceStr = self.get_nonceStr(15)
        self.timestamp = str(int(time.time()))

    def get_nonceStr(self, length):
        """随机数"""
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

    def get_pay3_sign(self, method, url, body=None):
        if body:
            _body = body
        else:
            _body = ''
        message = method + "\n" + url + "\n" + str(self.timestamp) + "\n" + self.nonceStr + "\n" + _body + "\n"
        SSLKEY_PATH = WxPayConf_OPEN_LJ.SSLKEY_PATH
        # 签名工具
        signer = PKCS1_v1_5.new(RSA.importKey(open(SSLKEY_PATH).read()))
        # 哈希后的消息
        hash_msg = SHA256.new(message.encode('utf-8'))
        # 生成签名 使用私钥进行'sha256'签名
        signature = signer.sign(hash_msg)
        sign = base64.encodestring(signature).decode("utf8").replace("\n", "")
        return sign

    def rsa_encrypt(self, message):
        """校验 RSA 加密"""
        public_key = self.get_AES_public_key()
        rsa_pubkey = RSA.import_key(public_key)
        cipher_pub = PKCS1_OAEP.new(rsa_pubkey)
        cipher_text = base64.b64encode(cipher_pub.encrypt(message.encode("utf-8")))
        return cipher_text

    def get_AES_public_key(self):
        key = self.pay3_conf.API_V3_KEY
        key_bytes = str.encode(key.encode('utf8'))
        pay_v3_open = PayV3OpenKey.objects.first()
        nonce_bytes = str.encode(pay_v3_open.nonce.encode('utf8'))
        ad_bytes = str.encode(pay_v3_open.associated_data.encode('utf8'))
        data = base64.b64decode(pay_v3_open.ciphertext.encode('utf8'))
        aesgcm = AESGCM(key_bytes)
        return aesgcm.decrypt(nonce_bytes, data, ad_bytes)

    def get_pay3_Authorization(self, sign, mch_id=WxPayConf_OPEN_LJ.MCHID):
        Authorization = 'WECHATPAY2-SHA256-RSA2048 mchid="{michid}",nonce_str="{nonce_str}",signature="{signature}",timestamp="{timestamp}",serial_no="{serial_no}"'.format(
            michid=mch_id, nonce_str=self.nonceStr, signature=sign, timestamp=self.timestamp,
            serial_no=self.pay3_conf.serial_No)
        return Authorization

    def get_pay_v3_certificates(self):
        method = 'GET'
        url = '/v3/certificates'
        sign = self.get_pay3_sign(method, url)
        headers = {
            'Content-Type': 'application/json',
            'Authorization': self.get_pay3_Authorization(sign)
        }
        _NET_URL = self.path + url
        response = requests.get(_NET_URL, headers=headers)
        return response.content

    def upload_img_pay3(self, file_name, file_path):
        """
        API V3上传图片
        file_path 存储本地的图片路径
        """
        url = '/v3/merchant/media/upload'
        file_sha256 = self.sha256_file(file_path)
        file_meta = {
            "sha256": file_sha256,
            "filename": file_name,
        }
        files = {"file": (file_name, open(file_path, 'rb'), 'image/png', {})}
        meta_json_str = json.dumps(file_meta)
        sign = self.get_pay3_sign('POST', url, meta_json_str)
        auth = self.get_pay3_Authorization(sign)
        headers = {
            'Authorization': auth
        }
        _NET_URL = self.path + url

        body = {
            "meta": meta_json_str,
        }
        response = requests.post(_NET_URL, data=body, headers=headers, files=files)
        return response.content

    def sha256_file(self, filepath):
        with open(filepath, 'rb') as f:
            return SHA256.new(f.read()).hexdigest()

    def get_date_str_format(self, _date):
        if len(_date) > 7:
            # 20201122
            return '%s-%s-%s' % (_date[0:4], _date[4:6], _date[6:8])
        else:
            # 长期
            return _date

    def mch_apply_apply(self):
        """
        API V3 提交申请单API
        """
        url = '/v3/applyment4sub/applyment/'
        mch_id = WxPayConf_OPEN_LJ.MCHID

        body = {}
        #  业务申请编号
        body['business_code'] = 'sma.business_code'

        #  超级管理员信息
        contact_info = {}
        contact_info['contact_name'] = 'self.rsa_encrypt(contact_name)'
        contact_info['contact_id_number'] = 'self.rsa_encrypt(contact_id_number)'
        contact_info['mobile_phone'] = 'self.rsa_encrypt(mobile_phone)'
        contact_info['contact_email'] = 'self.rsa_encrypt(contact_email)'
        body['contact_info'] = contact_info
        #  主体资料
        subject_info = {}
        subject_info['subject_type'] = 'subject_type'
        business_license_info = {}
        business_license_info['license_copy'] = 'license_copy'
        business_license_info['license_number'] = 'license_number'
        business_license_info['merchant_name'] = 'merchant_name'
        business_license_info['legal_person'] = 'legal_person'
        subject_info['business_license_info'] = 'business_license_info'

        # 经营者/法人身份证件
        id_card_info = {}
        id_card_info['id_card_copy'] = 'id_card_copy_MediaID'
        id_card_info['id_card_national'] = 'id_card_national_MediaID'
        id_card_info['id_card_name'] = 'self.rsa_encrypt(id_card_name)'
        id_card_info['id_card_number'] = 'self.rsa_encrypt(id_card_number)'
        id_card_info['card_period_begin'] = 'self.get_date_str_format(card_period_begin)'
        id_card_info['card_period_end'] = 'self.get_date_str_format(card_period_end)'

        identity_info = {}
        identity_info['id_card_info'] = id_card_info
        identity_info['owner'] = True
        identity_info['id_doc_type'] = 'id_doc_type'
        subject_info['identity_info'] = 'identity_info'

        body['subject_info'] = 'subject_info'

        #  经营资料
        business_info = {}
        business_info['merchant_shortname'] = 'merchant_shortname'
        business_info['service_phone'] = 'service_phone'

        mp_info = {}
        mp_info['mp_appid'] = 'mp_appid'

        sales_info = {}
        sales_info['mp_info'] = mp_info
        sales_info['sales_scenes_type'] = ['sales_scenes_type']

        business_info['sales_info'] = sales_info
        body['business_info'] = business_info

        #  结算规则
        settlement_info = {}
        settlement_info['settlement_id'] = 'settlement_id'
        settlement_info['qualification_type'] = 'qualification_type'
        body['settlement_info'] = settlement_info

        #  结算银行账户
        bank_account_info = {}
        bank_account_info['bank_account_type'] = 'qualification_type'
        bank_account_info['account_name'] = 'self.rsa_encrypt(account_name)'
        bank_account_info['account_bank'] = 'account_bank'
        bank_account_info['bank_address_code'] = 'bank_address_code'
        bank_account_info['account_number'] = 'self.rsa_encrypt(account_number)'
        body['bank_account_info'] = bank_account_info

        json_dump_json = json.dumps(body)
        sign = self.get_pay3_sign('POST', url, json_dump_json)
        Authorization = self.get_pay3_Authorization(sign)
        pay_v3_key = PayV3OpenKey.objects.first()
        serial_no = pay_v3_key.serial_no
        headers = {
            'Content-Type': 'application/json',
            'Authorization': Authorization,
            'Wechatpay-Serial': serial_no
        }
        _NET_URL = self.path + url

        response = requests.post(_NET_URL, data=json_dump_json, headers=headers)
        return response.content

    def get_mch_apply_status(self, business_code):
        method = 'GET'
        url = '/v3/applyment4sub/applyment/business_code/' + business_code
        sign = self.get_pay3_sign(method, url)
        headers = {
            'Content-Type': 'application/json',
            'Authorization': self.get_pay3_Authorization(sign)
        }
        _NET_URL = self.path + url
        response = requests.get(_NET_URL, headers=headers)
        return response.content
