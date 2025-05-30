# simplefinal/backend/db.py

# 用一个最简单的 dict 当「假数据库」
_store: dict[str, dict[str, str | bool]] = {}

def save_totp_secret(user_id: str, secret: str) -> None:
    """存下这个 user 的 TOTP secret，并默认还没启用 2FA"""
    _store[user_id] = {"secret": secret, "enabled": False}

def get_totp_secret(user_id: str) -> str:
    """取出存在 _store 里的 secret"""
    entry = _store.get(user_id)
    if not entry:
        raise KeyError(f"No TOTP secret for {user_id}")
    return entry["secret"]  # type: ignore

def enable_totp(user_id: str) -> None:
    """把这个 user 的 2FA 标记设为已启用"""
    if user_id not in _store:
        raise KeyError(f"No TOTP secret for {user_id}")
    _store[user_id]["enabled"] = True  # type: ignore
