import os
import secrets
import sqlite3
import uuid
import imghdr
from flask import Flask, render_template, request, redirect, session, url_for, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

# Session 安全配置
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# 上传配置
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 允许上传的图片类型
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "bmp", "webp"}
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/gif", "image/bmp", "image/webp"}


def allowed_file(filename):
    """检查文件扩展名是否合法"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


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
            phone TEXT,
            balance INTEGER DEFAULT 0
        )
    """)
    # 插入默认用户（密码以明文存储便于演示）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000", 99999))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001", 100))
    conn.commit()
    # 兼容旧表：如果 balance 列不存在则添加
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # 列已存在
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


@app.errorhandler(413)
def too_large(e):
    return render_template("upload.html", error="文件过大！最大允许 16MB"), 413


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
                filename = f.filename

                # 检查文件扩展名
                if not allowed_file(filename):
                    error = "不支持的文件类型，仅允许上传图片文件（jpg、png、gif、bmp、webp）"
                else:
                    # 检查 MIME 类型
                    mime_type = f.content_type
                    if mime_type not in ALLOWED_MIME_TYPES:
                        error = f"文件内容类型不合法（{mime_type}），仅允许上传图片"
                    else:
                        # 读取文件头验证是否为真实图片
                        file_data = f.read(512)
                        image_type = imghdr.what(None, file_data)
                        if image_type is None:
                            error = "文件内容不是有效的图片格式"
                        else:
                            # 重置文件指针
                            f.seek(0)

                            # 使用 UUID 重命名文件，防止路径穿越和文件覆盖
                            ext = filename.rsplit(".", 1)[1].lower()
                            safe_filename = f"{uuid.uuid4().hex}.{ext}"
                            save_path = os.path.normpath(os.path.join(UPLOAD_FOLDER, safe_filename))

                            # 确保路径仍在 UPLOAD_FOLDER 内（二次防护）
                            if not save_path.startswith(os.path.normpath(UPLOAD_FOLDER)):
                                error = "非法的文件路径"
                            else:
                                f.save(save_path)
                                uploaded_file = safe_filename
                                print(f"[UPLOAD] {session['username']} 上传了文件: {filename} -> {safe_filename}")

    return render_template("upload.html", uploaded_file=uploaded_file, error=error)


@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect(url_for("login"))

    user_id = request.args.get("user_id", "")
    user_data = None
    error = None

    if user_id:
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, username, email, phone, balance FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if row:
            user_data = dict(row)
        else:
            error = "用户不存在"
        conn.close()
    else:
        # 默认查询当前登录用户对应的 ID
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, username, email, phone, balance FROM users WHERE username = ?", (session["username"],))
        row = c.fetchone()
        if row:
            user_data = dict(row)
        conn.close()

    return render_template("profile.html", user=user_data, error=error)


@app.route("/recharge", methods=["POST"])
def recharge():
    if "username" not in session:
        return redirect(url_for("login"))

    user_id = request.form.get("user_id", "")
    amount = request.form.get("amount", "0")

    try:
        amount = int(amount)
    except ValueError:
        amount = 0

    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
    conn.commit()
    conn.close()

    # 同步 USERS 字典中的余额
    c = sqlite3.connect("data/users.db")
    c.row_factory = sqlite3.Row
    cur = c.cursor()
    cur.execute("SELECT username, balance FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    c.close()
    if row and row["username"] in USERS:
        USERS[row["username"]]["balance"] = row["balance"]

    return redirect(url_for("profile", user_id=user_id))


@app.route("/page")
def page():
    name = request.args.get("name", "")

    if not name:
        return render_template("index.html", page_content="请指定页面名称")

    # 直接拼接用户输入的 name 到路径中（有意留路径穿越漏洞）
    page_path = os.path.join("pages", name)
    content = None

    if os.path.isfile(page_path):
        with open(page_path, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        # 尝试加上 .html 后缀
        page_path_html = page_path + ".html"
        if os.path.isfile(page_path_html):
            with open(page_path_html, "r", encoding="utf-8") as f:
                content = f.read()

    if content is None:
        content = "页面不存在"

    username = session.get("username")
    user = None
    if username and username in USERS:
        user = {k: v for k, v in USERS[username].items() if k != "password"}

    return render_template("index.html", user=user, page_content=content)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
