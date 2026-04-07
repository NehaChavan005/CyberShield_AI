import os

from dotenv import load_dotenv


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOTENV_PATH = os.path.join(BASE_DIR, ".env")
DOTENV_EXAMPLE_PATH = os.path.join(BASE_DIR, ".env.example")


def load_project_env() -> None:
    if os.path.exists(DOTENV_PATH):
        load_dotenv(DOTENV_PATH, override=False)
    elif os.path.exists(DOTENV_EXAMPLE_PATH):
        load_dotenv(DOTENV_EXAMPLE_PATH, override=False)
