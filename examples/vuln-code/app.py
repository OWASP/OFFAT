import os, sqlite3, hashlib, pickle, subprocess, requests

API_KEY = "AKIAIOSFODNN7EXAMPLE"
password = "supersecretpassword123"

def get_user(db, uid):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id = '%s'" % uid)  # SQLi
    return cur.fetchone()

def run(cmd):
    os.system("echo " + cmd)  # command injection
    subprocess.run(cmd, shell=True)

def load(data):
    return pickle.loads(data)  # unsafe deserialization

def digest(x):
    return hashlib.md5(x).hexdigest()  # weak hash

def fetch(url):
    return requests.get(url, verify=False)  # SSRF + TLS off

if __name__ == "__main__":
    app_debug = True
