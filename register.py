import re
import hashlib
import time
import random
import string
import sqlite3
import os
import subprocess
from RSA_crypto import RSAServices
# 本地文档路径（存储用户信息）
LOCAL_DOC = "user_registry.txt"
# 需忽略的敏感文件（防止GitHub泄露密码数据）
SENSITIVE_FILES = [LOCAL_DOC, "ecommerce.db"]


def write_to_doc(user_info):
    """将用户信息写入本地文档（格式：时间戳|用户名|密码哈希|手机号，避免明文）"""
    with open(LOCAL_DOC, "a", encoding="utf-8") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        # 存储哈希后的密码，不存明文
        doc_line = (f"{timestamp}|{user_info['username']}|{user_info['pwd_hash']}|"
                    f"{user_info['phone_encrypted']}|{user_info.get('email_encrypted', '')}\n")
        f.write(doc_line)
    print(f"用户信息已保存到本地文档：{LOCAL_DOC}")


def ensure_gitignore():
    """自动生成/更新.gitignore，强制忽略敏感文件"""
    gitignore_path = ".gitignore"
    # 读取现有内容
    existing_content = []
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r", encoding="utf-8") as f:
            existing_content = f.read()

    # 追加缺失的敏感文件规则
    with open(gitignore_path, "a", encoding="utf-8") as f:
        for file in SENSITIVE_FILES:
            if file not in existing_content:
                f.write(f"\n# 敏感数据文件（自动添加，禁止GitHub同步）\n{file}")
    print(f".gitignore已配置：敏感文件{SENSITIVE_FILES}不会同步到GitHub")


def sync_to_github():
    """安全同步到GitHub：仅同步代码等非敏感文件，跳过敏感数据"""
    # 检查是否为Git仓库
    if not os.path.exists(".git"):
        print("\n【GitHub同步提示】当前目录不是Git仓库，需先执行：")
        print("1. 初始化Git：git init")
        print("2. 关联远程仓库：git remote add origin <你的GitHub仓库地址>")
        return

    # 询问用户是否同步
    sync_choice = input("\n是否将非敏感文件（代码、配置）同步到GitHub？(y/n)：").strip().lower()
    if sync_choice != "y":
        print("已取消GitHub同步")
        return

    try:
        # 暂存文件（.gitignore会自动过滤敏感文件）
        subprocess.run(["git", "add", "."], check=True, capture_output=True, text=True)
        # 提交信息（含时间戳）
        commit_msg = f"Update user management code: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        subprocess.run(["git", "commit", "-m", commit_msg], check=True, capture_output=True, text=True)
        # 推送到GitHub（默认main分支，可按需修改）
        subprocess.run(["git", "push", "-u", "origin", "main"], check=True, capture_output=True, text=True)
        print("【GitHub同步成功】仅非敏感文件已上传，敏感数据未同步")
    except subprocess.CalledProcessError as e:
        print(f"【GitHub同步失败】错误信息：{e.stderr}")


def generate_random_string(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def check_username(username):
    if not 6 <= len(username) <= 20:
        return False, "用户名长度需在6-20位之间"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "用户名仅可包含字母、数字和下划线"
    return True, "用户名合法"


def check_password_strength(password):
    if len(password) < 8:
        return False, "密码长度需≥8位"
    if not any(c.isupper() for c in password):
        return False, "密码需包含大写字母"
    if not any(c.islower() for c in password):
        return False, "密码需包含小写字母"
    if not any(c.isdigit() for c in password):
        return False, "密码需包含数字"
    if not any(c in "!@#$%^&*()_+{}|:\"<>?`~-=[]\\;',./" for c in password):
        return False, "密码需包含特殊字符（!@#$%^&*()等）"
    return True, "密码强度符合要求"


def check_phone(phone):
    if not re.match(r'^1[3-9]\d{9}$', phone):
        return False, "手机号格式不合法"
    return True, "手机号合法"


def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


# 初始化数据库连接
conn = sqlite3.connect('ecommerce.db')
cursor = conn.cursor()

# 创建用户表
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    fail_count INTEGER DEFAULT 0,
    phone_encrypted TEXT NOT NULL,
    phone TEXT NOT NULL
)
''')

# 创建会话表
cursor.execute('''
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    expire_time REAL NOT NULL,
    FOREIGN KEY (username) REFERENCES users (username)
)
''')
conn.commit()


# -------------------------- 注册函数新增“写入本地文档”逻辑 --------------------------
def register():
    print("=== 用户注册 ===")
    username = input("请输入用户名：")
    username_valid, username_msg = check_username(username)
    if not username_valid:
        print(username_msg)
        return

    password = input("请输入密码：")
    pwd_valid, pwd_msg = check_password_strength(password)
    if not pwd_valid:
        print(pwd_msg)
        return
    password_hash = hash_password(password)

    phone = input("请输入手机号：")
    phone_valid, phone_msg = check_phone(phone)
    if not phone_valid:
        print(phone_msg)
        return
        # 初始化RSA服务
    rsa_service = RSAServices()
    rsa_service.load_keys(e=65537)

    # 加密敏感信息
    try:
        encrypted_phone = rsa_service.encrypt(phone)
        print("✅ 敏感信息加密完成")
        print(f"加密手机号: {encrypted_phone[:30]}...")
    except Exception as e:
        print(f"❌ 加密失败: {e}")
        return

    # 1. 写入SQLite数据库
    try:
        cursor.execute('''
                INSERT INTO users (username, password_hash,phone, phone_encrypted)
                VALUES (?, ?, ?, ?)
                ''', (username, password_hash,phone, encrypted_phone))
        conn.commit()
        print("注册成功！加密数据已写入SQLite数据库")
    except sqlite3.IntegrityError:
        print("用户名已存在")
        return

    # 2. 写入本地文档
    user_info = {
        "username": username,
        "pwd_hash": password_hash,
        "phone_encrypted": encrypted_phone,
    }
    write_to_doc(user_info)

    # 3. 提示GitHub同步
    sync_to_github()


# -------------------------- 功能：会话与登录 --------------------------
def init_session(username, client_ip, user_agent):
    session_id = generate_random_string()
    expire_time = time.time() + 30 * 60  # 30分钟过期
    cursor.execute('''
    INSERT INTO sessions (session_id, username, client_ip, user_agent, expire_time)
    VALUES (?, ?, ?, ?, ?)
    ''', (session_id, username, client_ip, user_agent, expire_time))
    conn.commit()
    print(f"会话创建成功，Session ID：{session_id}")
    return session_id


def verify_session(session_id, client_ip, user_agent):
    cursor.execute('''
    SELECT username, client_ip, user_agent, expire_time
    FROM sessions
    WHERE session_id = ?
    ''', (session_id,))
    session = cursor.fetchone()
    if not session:
        return False, "Session 不存在，请重新登录"

    username, db_client_ip, db_user_agent, expire_time = session
    if time.time() > expire_time:
        cursor.execute('''
        DELETE FROM sessions
        WHERE session_id = ?
        ''', (session_id,))
        conn.commit()
        return False, "Session 已过期，请重新登录"

    if db_client_ip != client_ip or db_user_agent != user_agent:
        cursor.execute('''
        DELETE FROM sessions
        WHERE session_id = ?
        ''', (session_id,))
        conn.commit()
        return False, "登录环境异常，请重新验证身份"

    # 刷新过期时间
    new_expire_time = time.time() + 30 * 60
    cursor.execute('''
    UPDATE sessions
    SET expire_time = ?
    WHERE session_id = ?
    ''', (new_expire_time, session_id))
    conn.commit()
    return True, "Session 验证通过"


def login():
    print("=== 用户登录 ===")
    username = input("请输入用户名：")
    cursor.execute('''
       SELECT password_hash, phone_encrypted, fail_count
       FROM users
       WHERE username = ?
       ''', (username,))

    user = cursor.fetchone()
    if not user:
        print("用户名不存在")
        return
    password_hash, encrypted_phone, fail_count = user

    if fail_count >= 5:
        print("账户已锁定，请1小时后重试")
        return

    password = input("请输入密码：")
    input_password_hash = hash_password(password)
    if input_password_hash != password_hash:
        cursor.execute('''
        UPDATE users
        SET fail_count = fail_count + 1
        WHERE username = ?
        ''', (username,))
        conn.commit()
        remaining = 5 - (fail_count + 1)
        print(f"账号或密码错误，剩余尝试次数：{remaining}")
        return

    # 登录成功，重置失败次数
    cursor.execute('''
    UPDATE users
    SET fail_count = 0
    WHERE username = ?
    ''', (username,))
    conn.commit()
    print("登录成功！")
    rsa_service = RSAServices()
    rsa_service.load_keys(65537)
    try:
        decrypted_phone = rsa_service.decrypt(encrypted_phone)
        print(f"📱 您的手机号: {decrypted_phone}")
    except Exception as e:
        print(f"⚠️ 信息显示失败: {e}")

    client_ip = input("请输入客户端IP（模拟）：")
    user_agent = input("请输入User-Agent（模拟，如Mozilla/5.0）：")
    session_id = init_session(username, client_ip, user_agent)

    verify_result, verify_msg = verify_session(session_id, client_ip, user_agent)
    print(verify_msg)


# -------------------------- 主程序：启动时配置.gitignore --------------------------
if __name__ == "__main__":
    # 启动先确保敏感文件被.gitignore忽略
    ensure_gitignore()
    # 原有功能菜单
    while True:
        print("\n=== 电子商务系统用户管理 ===")
        print("1. 注册（自动存本地文档+支持GitHub同步）")
        print("2. 登录")
        print("3. 退出")
        choice = input("请选择操作：")

        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            print("感谢使用，再见！")
            conn.close()
            break
        else:
            print("无效选择，请重试")