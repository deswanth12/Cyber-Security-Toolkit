import sqlite3

conn = sqlite3.connect("security_toolkit.db")

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT,
    result TEXT,
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()


def save_activity(tool, result):

    conn = sqlite3.connect("security_toolkit.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO activity(tool, result) VALUES(?, ?)",
        (tool, result)
    )

    conn.commit()
    conn.close()


def get_history():

    conn = sqlite3.connect("security_toolkit.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM activity ORDER BY id DESC"
    )

    data = cursor.fetchall()

    conn.close()

    return data
def get_stats():

    conn = sqlite3.connect("security_toolkit.db")
    cursor = conn.cursor()

    stats = {}

    cursor.execute("SELECT COUNT(*) FROM activity")
    stats["total"] = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM activity WHERE tool='Password Analyzer'"
    )
    stats["passwords"] = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM activity WHERE tool='Port Scanner'"
    )
    stats["ports"] = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM activity WHERE tool='URL Inspector'"
    )
    stats["urls"] = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM activity WHERE tool='Hash Generator'"
    )
    stats["hashes"] = cursor.fetchone()[0]

    conn.close()

    return stats