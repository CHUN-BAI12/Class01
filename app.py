import os
import secrets
import sqlite3
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

# Session 安全配置
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# 上传配置
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    # 插入默认用户（密码以明文存储便于演示）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()


# 启动时初始化数据库
init_db()


@app.context_processor
def inject_csrf_token():
    """向所有模板注入 CSRF token"""
    def csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        return session["csrf_token"]
    return dict(csrf_token=csrf_token)


def verify_csrf():
    """验证 CSRF token"""
    token = request.form.get("csrf_token", "")
    return token and token == session.get("csrf_token", "")

# 用户数据库 - 密码使用哈希存储
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


@app.route("/")
def index():
    username = session.get("username")
    user = None
    if username and username in USERS:
        # 返回用户信息时排除密码字段
        user = {k: v for k, v in USERS[username].items() if k != "password"}
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not verify_csrf():
            return render_template("login.html", error="表单验证失败，请重试")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username in USERS and check_password_hash(USERS[username]["password"], password):
            session["username"] = username
            session.permanent = True
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        # 使用 f-string 拼接 SQL（有意留漏洞）
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        print(f"[SQL] {sql}")
        try:
            c.execute(sql)
            conn.commit()
            conn.close()
            return redirect(url_for("login", registered="1"))
        except Exception as e:
            conn.close()
            return render_template("register.html", error=f"注册失败：{str(e)}")
    return render_template("register.html")


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    results = []
    if keyword:
        # 使用 f-string 拼接 SQL（有意留漏洞）
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[SQL] {sql}")
        c.execute(sql)
        rows = c.fetchall()
        for row in rows:
            results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})
        conn.close()

    username = session.get("username")
    user = None
    if username and username in USERS:
        user = {k: v for k, v in USERS[username].items() if k != "password"}

    return render_template("index.html", user=user, results=results, keyword=keyword)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect(url_for("login"))

    uploaded_file = None
    error = None

    if request.method == "POST":
        if "file" not in request.files:
            error = "没有选择文件"
        else:
            f = request.files["file"]
            if f.filename == "":
                error = "没有选择文件"
            else:
                # 使用原始文件名保存，不做任何检查
                filename = f.filename
                f.save(os.path.join(UPLOAD_FOLDER, filename))
                uploaded_file = filename
                print(f"[UPLOAD] {session['username']} 上传了文件: {filename}")

    return render_template("upload.html", uploaded_file=uploaded_file, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
