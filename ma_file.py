from base64 import b64encode


def decode_secret(secret):
    return b64encode(secret).decode('utf-8')


def get_shared_secret(auth):
    return decode_secret(auth.shared_secret)


def get_identity_secret(auth):
    return decode_secret(auth.identity_secret)


def get_secret_1(auth):
    return decode_secret(auth.secret_1)


class MaFile:
    def __init__(self, auth, steam_id, access_token, refresh_token, session_id, device_id):
        self.shared_secret = get_shared_secret(auth)
        self.serial_number = auth.serial_number
        self.revocation_code = auth.revocation_code
        self.uri = auth.uri
        self.server_time = auth.server_time
        self.account_name = auth.account_name
        self.token_gid = auth.token_gid
        self.identity_secret = get_identity_secret(auth)
        self.secret_1 = get_secret_1(auth)
        self.status = auth.status
        self.device_id = device_id
        self.fully_enrolled = True
        self.Session = {
            "SteamID": steam_id,
            "AccessToken": access_token,
            "RefreshToken": refresh_token,
            "SessionID": session_id
        }

    def to_dict(self):
        return {
            "shared_secret": self.shared_secret,
            "serial_number": self.serial_number,
            "revocation_code": self.revocation_code,
            "uri": self.uri,
            "server_time": self.server_time,
            "account_name": self.account_name,
            "token_gid": self.token_gid,
            "identity_secret": self.identity_secret,
            "secret_1": self.secret_1,
            "status": self.status,
            "device_id": self.device_id,
            "fully_enrolled": self.fully_enrolled,
            "Session": self.Session
        }
