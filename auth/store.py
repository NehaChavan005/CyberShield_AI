import json
import os

from auth.config import DEMO_FULL_NAME, DEMO_PASSWORD, DEMO_USERNAME
from auth.security import hash_password, verify_password


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_DB_PATH = os.path.join(BASE_DIR, "data", "users.json")


def _demo_user():
    return {
        DEMO_USERNAME: {
            "username": DEMO_USERNAME,
            "full_name": DEMO_FULL_NAME,
            "hashed_password": hash_password(DEMO_PASSWORD),
            "source": "demo",
        }
    }


def _load_persisted_users():
    if not os.path.exists(USERS_DB_PATH):
        return {}

    try:
        with open(USERS_DB_PATH, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}

    if not isinstance(payload, dict):
        return {}
    return payload


def _save_persisted_users(users):
    os.makedirs(os.path.dirname(USERS_DB_PATH), exist_ok=True)
    with open(USERS_DB_PATH, "w", encoding="utf-8") as handle:
        json.dump(users, handle, indent=2)


def load_user_db() -> dict:
    users = _demo_user()
    users.update(_load_persisted_users())
    return users


USER_DB = load_user_db()


def refresh_user_db() -> dict:
    global USER_DB
    USER_DB = load_user_db()
    return USER_DB


def get_user(username: str) -> dict | None:
    if not username:
        return None
    refresh_user_db()
    return USER_DB.get(username)


def authenticate_user(username: str, password: str) -> dict | None:
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return {"username": user["username"], "full_name": user["full_name"]}


def create_user(username: str, full_name: str, password: str) -> tuple[bool, str]:
    username = str(username or "").strip()
    full_name = str(full_name or "").strip()
    password = str(password or "")

    if not username or not full_name or not password:
        return False, "Username, full name, and password are required."
    if " " in username:
        return False, "Username cannot contain spaces."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    persisted_users = _load_persisted_users()
    if username == DEMO_USERNAME or username in persisted_users:
        return False, "That username already exists."

    persisted_users[username] = {
        "username": username,
        "full_name": full_name,
        "hashed_password": hash_password(password),
        "source": "signup",
    }
    _save_persisted_users(persisted_users)
    refresh_user_db()
    return True, "Account created successfully. You can sign in now."
