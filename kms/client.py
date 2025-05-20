import requests

def wrap_key(key: bytes) -> bytes:
    # 假裝回傳包裝好的 key（用 key 加個前綴模擬）
    return b"wrapped_" + key

def unwrap_key(wrapped: bytes) -> bytes:
    # 假裝解包，去掉前綴模擬還原
    if wrapped.startswith(b"wrapped_"):
        return wrapped[len(b"wrapped_"):]
    return b""  # 如果格式不對，回空bytes

