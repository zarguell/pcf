import json
import sqlite3


def note_type_add(config, db):
    print("This script will add a new field to 'Notes' table - type. This field will be text, docs,...")
    print("More info: https://gitlab.com/invuls/pentest-projects/pcf/-/issues/156")
    print("Fixing Notes table")
    try:
        db.execute("ALTER TABLE Notes ADD `type` text default 'html';")
        db.conn.commit()
    except sqlite3.OperationalError as e:
        print("Don't need to add a new column!")
    print("Fixed Notes table!")

