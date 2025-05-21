import pymysql
import bcrypt

# Connect to the database
conn = pymysql.connect(
    host='localhost',
    user='root',
    password='1234',
    database='employee'
)

cur = conn.cursor()
cur.execute("SELECT username, password FROM users")
users = cur.fetchall()

for username, password in users:
    # Skip already hashed passwords
    if not password.startswith('$2b$'):
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cur.execute("UPDATE users SET password=%s WHERE username=%s", (hashed.decode('utf-8'), username))

conn.commit()
conn.close()
print("✅ Passwords hashed successfully.")
