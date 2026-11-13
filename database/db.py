import sqlite3
from flask import current_app, g

def get_db():
    if "db" not in g:
        g.db=sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory=sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

def init_db():
    db=get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS analyses(id INTEGER PRIMARY KEY AUTOINCREMENT,sender TEXT NOT NULL,recipient TEXT,subject TEXT NOT NULL,body TEXT NOT NULL,verdict TEXT NOT NULL,score INTEGER NOT NULL,risk TEXT NOT NULL,keywords TEXT,urls TEXT,flags TEXT,explanation TEXT,recommendations TEXT,created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS extracted_urls(id INTEGER PRIMARY KEY AUTOINCREMENT,analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,url TEXT NOT NULL,score INTEGER NOT NULL,indicators TEXT);
    CREATE TABLE IF NOT EXISTS detected_indicators(id INTEGER PRIMARY KEY AUTOINCREMENT,analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,title TEXT NOT NULL,detail TEXT NOT NULL,weight INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(id DESC);
    """)
    db.commit()

def close_db(error=None):
    db=g.pop("db",None)
    if db is not None: db.close()
