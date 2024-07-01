import time
import re
import poplib
from email.parser import BytesParser
import ssl
import certifi

# 邮件服务器配置
check_interval = 1  # 检查间隔（秒）


class SteamMail:
    def __init__(self, mail_server, acc_name, mail_acc, mail_password):
        self.acc_name = acc_name
        self.mail_acc = mail_acc
        self.mail_server = mail_server
        self.mail_password = mail_password
        self.last_email_count = 0

    def set_last_email_count(self):
        try:
            print('set_last_email_count')
            print(self.mail_server)
            print(self.mail_acc)
            print(self.mail_password)
            # 连接到POP3邮件服务器
            print('get_pop3_ssl_linking....')
            mail = poplib.POP3_SSL('outlook.office365.com')
            print('连接到POP3邮件服务器')
            mail.user(self.mail_acc)
            mail.pass_(self.mail_password)
            num_messages = len(mail.list()[1])
            print(f"Number of messages: {num_messages}")
            self.last_email_count = num_messages
        except poplib.error_proto as e:
            print(f"POP3 error: {e}")

    def get_steam_code(self):
        verification_code = None
        attempt = 0
        max_attempts = 6
        try:
            while attempt < max_attempts:
                # 连接到POP3邮件服务器
                mail = poplib.POP3_SSL(self.mail_server)
                mail.user(self.mail_acc)
                mail.pass_(self.mail_password)

                # 获取邮件列表
                num_messages = len(mail.list()[1])

                if num_messages > self.last_email_count:
                    new_email_count = num_messages - self.last_email_count
                    for i in range(new_email_count):
                        # 获取最新的邮件
                        response, lines, octets = mail.retr(num_messages - i)
                        msg_data = b'\r\n'.join(lines)
                        msg = BytesParser().parsebytes(msg_data)

                        # 检查邮件内容是否包含特定的用户名
                        # 打印 邮件内容
                        email_content = None
                        for part in msg.walk():
                            if part.get_content_type() == 'text/plain':
                                email_content = part.get_payload(decode=True).decode(part.get_content_charset())
                            else:
                                continue
                        verification_code = self.find_verification_code(email_content)
                        if verification_code:
                            print(f"Found verification code: {verification_code}")
                            break
                        else:
                            print("No verification code found")
                    self.last_email_count = num_messages
                mail.quit()
                if verification_code:
                    return True, verification_code
                print("No new emails. Waiting for new emails...")
                time.sleep(check_interval)
                attempt += 1
            return False, None
        except Exception as e:
            print(f"Error: {e}")
            return False, None

    def find_verification_url(self, email_content):
        # 使用正则表达式提取验证电子邮箱的URL
        verification_url = None
        urls = re.findall(r'https?://[^\s]+', email_content)
        for url in urls:
            if 'newaccountverification' in url:
                verification_url = url
                break

        # 打印提取的URL
        if verification_url:
            print(f"验证电子邮箱的地址: {verification_url}")
            return verification_url
        else:
            print("未找到验证电子邮箱的地址")
            return None

    def find_verification_code(self, email_content):
        # 判断内容是否有 self.acc_name
        if self.acc_name not in email_content:
            print("未找到账户名")
            return None
        # 正则表达式匹配验证码
        pattern = re.compile(r'<td class="title-48 c-blue1 fw-b a-center".*?>(.*?)</td>', re.DOTALL)
        match = pattern.search(email_content)

        if match:
            auth_code = match.group(1).strip()
            print(f"提取到的验证码: {auth_code}")
            return auth_code
        else:
            print("未找到验证码")
            return None
