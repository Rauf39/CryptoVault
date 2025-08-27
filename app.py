from flask import Flask, render_template, request, redirect, url_for, flash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256
import os, json, base64

app = Flask(__name__)
app.secret_key = "supersecretkey"

FILE_NAME = "vault.enc"
BLOCK_SIZE = 16

# ================= Crypto Functions ==================
def pad(data):
    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding]) * padding

def unpad(data):
    return data[:-data[-1]]

def get_key(password: str):
    return sha256(password.encode()).digest()

def encrypt_data(data, password):
    key = get_key(password)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data.encode()))
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_data(ciphertext, password):
    key = get_key(password)
    raw = base64.b64decode(ciphertext)
    iv = raw[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        plaintext = unpad(cipher.decrypt(raw[16:]))
        return plaintext.decode()
    except:
        return None

def load_vault(password):
    if not os.path.exists(FILE_NAME):
        return {}
    with open(FILE_NAME, "r") as f:
        data = f.read()
    decrypted = decrypt_data(data, password)
    if decrypted is None:
        return None
    return json.loads(decrypted)

def save_vault(vault, password):
    data = json.dumps(vault)
    encrypted = encrypt_data(data, password)
    with open(FILE_NAME, "w") as f:
        f.write(encrypted)

# ================= Flask Routes ==================
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        master_password = request.form["master_password"]
        vault = load_vault(master_password)
        if vault is None:
            flash("❌ Wrong master password or vault corrupted!", "danger")
            return redirect(url_for("index"))
        return redirect(url_for("dashboard", mp=master_password))
    return render_template("index.html")

@app.route("/dashboard/<mp>", methods=["GET", "POST"])
def dashboard(mp):
    vault = load_vault(mp)
    if vault is None:
        flash("❌ Access denied!", "danger")
        return redirect(url_for("index"))
    if request.method == "POST":
        account = request.form["account"]
        pwd = request.form["password"]
        vault[account] = pwd
        save_vault(vault, mp)
        flash("✅ Entry saved!", "success")
    return render_template("dashboard.html", vault=vault)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
