from flask import Flask, request, jsonify
import jwt
import time
import sqlite3
import os

app = Flask(__name__)

# 从环境变量获取密钥（安全性更高）
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")  # 默认值供本地测试

# 初始化SQLite数据库
def init_db():
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS accounts 
                 (account_id TEXT PRIMARY KEY, username TEXT, password TEXT)''')
    # 插入测试数据
    c.execute("INSERT OR IGNORE INTO accounts VALUES (?, ?, ?)",
              ("my_account", "user123", "pass123"))
    conn.commit()
    conn.close()

@app.route('/verify_key', methods=['GET'])
def verify_key():
    key = request.args.get('key')
    if not key:
        return jsonify({"error": "缺少秘钥"}), 400

    try:
        # 解析JWT
        payload = jwt.decode(key, SECRET_KEY, algorithms=["HS256"])
        account_id = payload["account_id"]
        exp_time = payload["exp"]

        # 检查是否过期
        if time.time() > exp_time:
            return jsonify({"error": "秘钥已过期"}), 403

        # 从数据库获取账号信息
        conn = sqlite3.connect("accounts.db")
        c = conn.cursor()
        c.execute("SELECT username, password FROM accounts WHERE account_id = ?", (account_id,))
        account = c.fetchone()
        conn.close()

        if not account:
            return jsonify({"error": "账号不存在"}), 404

        return jsonify({"username": account[0], "password": account[1]}), 200

    except jwt.InvalidTokenError:
        return jsonify({"error": "秘钥无效"}), 401

# 健康检查路由（Render要求）
@app.route('/', methods=['GET'])
def health_check():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    init_db()  # 初始化数据库
    port = int(os.getenv("PORT", 10000))  # Render默认端口10000
    app.run(host="0.0.0.0", port=port)
