from datetime import datetime

def log_event(user_id: str, action: str, metadata: dict = {}):
    with open("audit.log", "a") as f:
        f.write(f"{datetime.now()} | {user_id} | {action} | {metadata}\n")
