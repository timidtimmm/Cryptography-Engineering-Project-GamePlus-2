# auth/webauthn.py
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

# 伺服器設定
rp = PublicKeyCredentialRpEntity(id="localhost", name="MyApp")
fido2_server = Fido2Server(rp)

# 模擬資料庫（實務上應抽換成 DB）
user_db = {}
challenge_db = {}

def start_registration(username: str):
    user_id = username.encode("utf-8")  # 保證唯一即可，實務上可用 UUID
    user = {"id": user_id, "name": username, "displayName": username}

    registration_data, state = fido2_server.register_begin(user, user_verification="preferred")
    challenge_db[username] = state
    return registration_data

def complete_registration(username: str, attestation):
    state = challenge_db.get(username)
    if not state:
        raise ValueError("No challenge found for user.")
    auth_data = fido2_server.register_complete(state, attestation)
    user_db[username] = auth_data.credential_data
    return True

def start_authentication(username: str):
    if username not in user_db:
        raise ValueError("User not registered.")
    credentials = [user_db[username]]

    auth_data, state = fido2_server.authenticate_begin(credentials)
    challenge_db[username] = state
    return auth_data

def complete_authentication(username: str, assertion):
    state = challenge_db.get(username)
    credentials = [user_db[username]]
    fido2_server.authenticate_complete(state, credentials, assertion)
    return True
