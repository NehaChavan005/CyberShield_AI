import os

from utils.env_loader import load_project_env


load_project_env()
from datetime import timedelta


JWT_SECRET_KEY = os.getenv(
    "CYBERSHIELD_JWT_SECRET",
    "change-this-in-production-at-least-32-bytes",
)
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("CYBERSHIELD_JWT_EXPIRE_MINUTES", "60"))

DEMO_USERNAME = os.getenv("CYBERSHIELD_DEMO_USERNAME", "admin")
DEMO_PASSWORD = os.getenv("CYBERSHIELD_DEMO_PASSWORD", "CyberShield123!")
DEMO_FULL_NAME = os.getenv("CYBERSHIELD_DEMO_FULL_NAME", "CyberShield Admin")


def token_expiry() -> timedelta:
    return timedelta(minutes=JWT_EXPIRE_MINUTES)
