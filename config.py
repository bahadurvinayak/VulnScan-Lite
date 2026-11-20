
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "vulnscan-lite-development-key"
    )

    DEBUG = False

    DATABASE = os.path.join(BASE_DIR, "vulnscan.db")

    REPORT_FOLDER = os.path.join(BASE_DIR, "reports")

    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
