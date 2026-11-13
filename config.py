"""Configuration defaults for local PhishGuard deployment."""
import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.environ.get("PHISHGUARD_DB", os.path.join(BASE_DIR, "phishguard.sqlite3"))
