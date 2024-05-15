import base64
import json
import logging
import os
from time import time
import uuid
from base64 import b64encode

import requests
import rsa
import secrets
from requests.exceptions import RequestException
from fake_useragent import UserAgent

from ma_file import MaFile
from sda_code import generator_code, get_time_offset, generate_twofactor_code_for_time
from steam_pb2 import (
    IAuthenticationGetPasswordRsaPublicKeyRequest,
    IAuthenticationGetPasswordRsaPublicKeyResponse,
    device_details,
    LoginRequest,
    LoginRespones,
    allowed_confirmations,
    PollAuthSessionStatus_Request,
    PollAuthSessionStatus_Response,
    UpdateAuthSessionWithSteamGuardCode
)
from twofactor_pb2 import (
    CTwoFactor_Time_Request,
    CTwoFactor_Time_Response,
    CTwoFactor_AddAuthenticator_Request,
    CTwoFactor_AddAuthenticator_Response,
    CTwoFactor_FinalizeAddAuthenticator_Request,
    CTwoFactor_FinalizeAddAuthenticator_Response,
)

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SteamAuth:
    def __init__(self, username, password, email, email_pwd):
        self.device_id = "android:" + str(uuid.uuid4())
        self.username = username
        self.password = password
        self.email = email
        self.email_pwd = email_pwd
        self.ua = UserAgent().chrome
        self.session_id = self.get_session_id()
        self.browser_id = self.get_browser_id()
        self.session = requests.session()
        self.session.verify = False
        self.headers = {
            'user-agent': self.ua
        }
        self.steam_id = None
        self.client_id = None
        self.request_id = None
        self.access_token = None
        self.refresh_token = None
        self.ma_file = None
        self.mail = None

    def get_session_id(self):
        bytes_length = 12
        session_id = secrets.token_hex(bytes_length)
        return str(session_id)

    def get_browser_id(self):
        min_value = 1
        max_value = 2 ** 63 - 1
        browser_id = secrets.randbelow(max_value) + min_value
        return str(browser_id)

    def generator_protobuf(self, message):
        return base64.b64encode(message.SerializeToString()).decode()

    '''
    根据用户名获取rsa密钥
    '''

    def get_rsa_public_key(self):
        origin = 'https://steamcommunity.com'
        message = IAuthenticationGetPasswordRsaPublicKeyRequest(
            account_name=self.username
        )
        protobuf = self.generator_protobuf(message)
        url = 'https://api.steampowered.com/IAuthenticationService/GetPasswordRSAPublicKey/v1'

        params = {
            "origin": origin,
            "input_protobuf_encoded": protobuf
        }

        attempt = 0
        max_attempts = 5
        while attempt < max_attempts:
            try:
                response = self.session.get(url, params=params, headers=self.headers, timeout=3)
                # 解析响应信息
                response = IAuthenticationGetPasswordRsaPublicKeyResponse.FromString(response.content)
                return True, response  # 成功时返回True和响应内容
            except RequestException as e:
                attempt += 1
                logging.error(f"Function : get_rsa_public_key ,Attempt {attempt} failed with exception: {e}")
                if attempt == max_attempts:
                    # 最后一次尝试失败，返回False和异常信息
                    return False, str(e)

    '''
    根据密钥加密信息
    '''

    def rsa_encrypt(self, pubkey_n, pubkey_e):
        # 将十六进制字符串转换为整数
        rsa_n = int(pubkey_n, 16)
        rsa_e = int(pubkey_e, 16)
        # 用n值和e值生成公钥
        key = rsa.PublicKey(rsa_n, rsa_e)
        # 用公钥把明文加密
        message = rsa.encrypt(self.password.encode(), key)
        message = base64.b64encode(message).decode()
        return message

    '''
    发送加密后的登陆信息
    '''

    def send_encode_request(self, encrypted_password, encryption_timestamp):
        url = f'https://api.steampowered.com/IAuthenticationService/BeginAuthSessionViaCredentials/v1'
        device_msg = device_details(
            device_friendly_name=self.ua,
            platform_type=2,
        )
        message = LoginRequest(
            account_name=self.username,
            encrypted_password=encrypted_password,
            encryption_timestamp=encryption_timestamp,
            set_remember_login=1,
            set_persistence=1,
            website_id="Store",
            device_details=[device_msg],
            language=0
        )
        protobuf = self.generator_protobuf(message)
        params = {
            "input_protobuf_encoded": protobuf
        }
        attempt = 0
        max_attempts = 5
        while attempt < max_attempts:
            try:
                response = self.session.post(url, params=params, headers=self.headers, timeout=5)
                response = LoginRespones.FromString(response.content)
                self.steam_id = response.steamid
                self.client_id = response.client_id
                self.request_id = response.request_id
                return True, response
            except RequestException as e:
                attempt += 1
                logging.error(f"Function : send_encode_request ,Attempt {attempt} failed with exception: {e}")
                if attempt == max_attempts:
                    # 最后一次尝试失败，返回False和异常信息
                    return False, str(e)

    '''
    验证验证码
    '''

    def auth_code(self, code):
        message = UpdateAuthSessionWithSteamGuardCode(
            client_id=self.client_id,
            steamId=self.steam_id,
            code=code,
            code_type=3,
        )
        protobuf = self.generator_protobuf(message)
        url = f'https://api.steampowered.com/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1'
        params = {
            "input_protobuf_encoded": protobuf
        }
        attempt = 0
        max_attempts = 5
        while attempt < max_attempts:
            try:
                response = requests.post(url, params=params, headers=self.headers)
                # if response.status_code != 200:
                #     return False, "网络状态返回错误"
                eresult = response.headers['X-eresult']  # 打印响应头部信息
                if eresult == '1':
                    return True
                else:
                    return False
            except RequestException as e:
                attempt += 1
                logging.error(f"Function : send_encode_request ,Attempt {attempt} failed with exception: {e}")
                if attempt == max_attempts:
                    # 最后一次尝试失败，返回False和异常信息
                    return False, str(e)
            except Exception as e:
                return False, str(e)

    def finalize_add_authenticator(self, email_code):
        url = f'https://api.steampowered.com/ITwoFactorService/FinalizeAddAuthenticator/v1/?access_token={self.access_token}'
        aligned_time = int(time() + get_time_offset())  # 补偿后的时间
        print(f'aligned_time: {aligned_time}')
        print(f'email_code: {email_code}')
        print(f'shared_secret: {self.ma_file.shared_secret}')
        code = generate_twofactor_code_for_time(str(self.ma_file.shared_secret), aligned_time)
        print(f'authenticator_code: {code}')
        message = CTwoFactor_FinalizeAddAuthenticator_Request(
            steamid=int(self.steam_id),
            activation_code=str(email_code),
            authenticator_time=int(aligned_time),
            authenticator_code=str(code),
            http_headers=self.headers,
        )
        protobuf = self.generator_protobuf(message)
        params = {
            "input_protobuf_encoded": protobuf
        }
        attempt = 0
        max_attempts = 5
        while attempt < max_attempts:
            try:
                response = requests.post(url, params=params, headers=self.headers, timeout=3)
                response = CTwoFactor_FinalizeAddAuthenticator_Response.FromString(response.content)
                print(response)
                if response:
                    return response.success
            except RequestException as e:
                attempt += 1
                logging.error(f"Function : add_authenticator ,Attempt {attempt} failed with exception: {e}")
                if attempt == max_attempts:
                    # 最后一次尝试失败，返回False和异常信息
                    return False, str(e)

    def login_email(self):
        return True

    '''
    获取增加令牌
    '''

    def add_authenticator(self):
        url = f'https://api.steampowered.com/ITwoFactorService/AddAuthenticator/v1/?access_token={self.access_token}'
        aligned_time = int(time() + get_time_offset())  # 补偿后的时间
        # 生成一个 UUID (128位)
        generated_uuid = uuid.uuid4()

        # 将 UUID 转换为整数，并取其前 64 位或后 64 位作为序列号
        # 这里取后64位
        serial_number = generated_uuid.int >> 64

        # 确保它是一个无符号 64 位整数
        serial_number_fixed64 = serial_number & ((1 << 64) - 1)
        message = CTwoFactor_AddAuthenticator_Request(
            steamid=int(self.steam_id),
            authenticator_time=int(aligned_time),
            serial_number=int(serial_number_fixed64),
            authenticator_type=1,
            device_identifier=self.device_id,
            http_headers=self.headers,
            version=1
        )
        protobuf = self.generator_protobuf(message)
        params = {
            "input_protobuf_encoded": protobuf
        }
        attempt = 0
        max_attempts = 5
        while attempt < max_attempts:
            try:
                response = requests.post(url, params=params, headers=self.headers, timeout=3)
                response = CTwoFactor_AddAuthenticator_Response.FromString(response.content)
                print(response)
                if response:
                    self.ma_file = MaFile(response, self.steam_id, self.access_token, self.refresh_token,
                                          self.session_id, self.device_id)
                    # 保存 self.ma_file 的信息 到 bind_file 文件夹 以便后续使用 文件名为 self.steam_id.maFile
                    self.save_ma_file()
                    print(b64encode(response.shared_secret).decode('utf-8'))
                    return True
                return False
            except RequestException as e:
                attempt += 1
                logging.error(f"Function : add_authenticator ,Attempt {attempt} failed with exception: {e}")
                if attempt == max_attempts:
                    # 最后一次尝试失败，返回False和异常信息
                    return False, str(e)

    def save_ma_file(self):
        # 定义保存文件的路径（项目根目录）和文件名
        directory = 'bind_file'
        if not os.path.exists(directory):
            os.makedirs(directory)

        file_name = f"{self.steam_id}.maFile"
        file_path = os.path.join(directory, file_name)

        # 将 self.ma_file 的内容保存为 JSON 文件
        with open(file_path, 'w') as file:
            json.dump(self.ma_file.to_dict(), file, indent=4)

        print(f"文件已保存到: {file_path}")

    '''
    获取token
    '''

    def get_token(self):
        url = f'https://api.steampowered.com/IAuthenticationService/PollAuthSessionStatus/v1'
        message = PollAuthSessionStatus_Request(
            ClientID=self.client_id,
            request_id=self.request_id
        )
        protobuf = self.generator_protobuf(message)
        params = {
            "input_protobuf_encoded": protobuf
        }
        attempt = 0
        max_attempts = 5
        while attempt < max_attempts:
            try:
                response = requests.post(url, params=params, headers=self.headers, timeout=3)
                response = PollAuthSessionStatus_Response.FromString(response.content)
                if response:
                    self.access_token = response.access_token
                    self.refresh_token = response.refresh_token
                    return True
                return False
            except RequestException as e:
                attempt += 1
                logging.error(f"Function : get_rsa_public_key ,Attempt {attempt} failed with exception: {e}")
                if attempt == max_attempts:
                    # 最后一次尝试失败，返回False和异常信息
                    return False, str(e)

    def get_mail_code(self):
        code = self.mail.get_steam_code()
        return True, code
