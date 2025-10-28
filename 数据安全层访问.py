from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base  # SQLAlchemy 2.0+ 新导入方式
from sqlalchemy.orm import sessionmaker, relationship
import logging
from datetime import datetime, timedelta
import jwt
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
import base64
import json
import random
import re
import hashlib
import time
import string
import os
import subprocess

# ========== 1. 数据库配置（已修改：替换占位符为通用默认配置） ==========
# 说明：本地MySQL默认用户多为root，需替换为你的实际用户名和密码
engine = create_engine(
    "sqlite:///ecommerce.db",
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
    pool_recycle=3600,
    echo=False  # 调试时可改为True，打印SQL语句
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()  # 使用新导入创建Base类

# ========== 2. RSA加密工具类（无修改，保留完整功能） ==========
class RSAServices:
    def __init__(self):
        self.path = "RSA_crypto.py"
        self.private_key = None  # 字典格式：{n, d, e, type, key_size}
        self.public_key = None   # 字典格式：{n, e, type, key_size}
        self.size = None

    @staticmethod
    def serialize(info):
        """序列化（列表/字典→Base64编码字符串）"""
        if isinstance(info, (list, dict)):
            json_str = json.dumps(info)
            return base64.b64encode(json_str.encode()).decode()

    @staticmethod
    def deserialize(serialize_data):
        """反序列化（Base64编码字符串→列表/字典）"""
        try:
            json_str = base64.b64decode(serialize_data.encode())
            return json.loads(json_str.decode("utf-8"))
        except Exception as e:
            print(f"反序列化失败：{e}")
            raise

    @staticmethod
    def is_prime(n):
        """素数检测（米勒-拉宾算法）"""
        if n % 2 == 0:
            return False
        d = n - 1
        s = 0
        while d % 2 == 0:
            s += 1
            d //= 2
        a = 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return True
        return False

    @staticmethod
    def get_prime(bits):
        """生成指定位数的素数"""
        while True:
            p = random.getrandbits(bits)
            p |= (1 << (bits - 1)) | 1  # 确保最高位和最低位为1
            if RSAServices.is_prime(p):
                return p

    @staticmethod
    def gra_pra_pub_key(e=65537):
        """生成RSA密钥对（字典格式）"""
        p = RSAServices.get_prime(1024)
        q = RSAServices.get_prime(1024)
        n = p * q
        phi_n = (p - 1) * (q - 1)
        d = pow(e, -1, phi_n)  # 计算私钥指数d
        private_key = {
            "type": "private",
            "n": n,
            "d": d,
            "e": e,
            "key_size": 1024
        }
        public_key = {
            "type": "public",
            "n": n,
            "e": e,
            "key_size": 1024
        }
        return private_key, public_key

    def load_keys(self, e=65537):
        """加载密钥对（优先从文件读取，失败则生成新密钥）"""
        try:
            with open("private_key.txt", "r", encoding="utf-8") as f:
                self.private_key = self.deserialize(f.read())
            with open("public_key.txt", "r", encoding="utf-8") as f:
                self.public_key = self.deserialize(f.read())
            print("✅ 密钥对加载成功")
        except Exception as e:
            print(f"❌ 密钥加载失败：{e}，将生成新密钥")
            self.generate_keys()

    def generate_keys(self):
        """生成并保存密钥对到本地文件"""
        self.private_key, self.public_key = self.gra_pra_pub_key(65537)
        # 序列化并保存私钥
        with open("private_key.txt", "w", encoding="utf-8") as f:
            f.write(self.serialize(self.private_key))
        # 序列化并保存公钥
        with open("public_key.txt", "w", encoding="utf-8") as f:
            f.write(self.serialize(self.public_key))
        print("✅ 新密钥对已生成并保存")

    def encrypt(self, info):
        """公钥加密（支持字符串类型数据）"""
        if self.public_key is None:
            raise RuntimeError("❌ 公钥未初始化，无法加密")
        # 确保info为字符串
        if not isinstance(info, str):
            info = str(info)
        m = bytes_to_long(info.encode('utf-8'))  # 明文→长整数
        n = self.public_key['n']
        e = self.public_key['e']
        # 检查数据长度（避免超过密钥容量）
        max_length = (self.public_key['key_size'] // 8) - 11
        if len(info.encode('utf-8')) > max_length:
            raise ValueError(f"❌ 数据过长，最大支持{max_length}字节")
        c = pow(m, e, n)  # 加密：m^e mod n
        encrypted_bytes = long_to_bytes(c)  # 密文长整数→字节
        return base64.b64encode(encrypted_bytes).decode('utf-8')  # 字节→Base64字符串

    def decrypt(self, encrypted_data):
        """私钥解密（输入Base64编码的密文）"""
        if self.private_key is None:
            raise RuntimeError("❌ 私钥未初始化，无法解密")
        encrypted_bytes = base64.b64decode(encrypted_data)  # Base64→字节
        c = bytes_to_long(encrypted_bytes)  # 字节→密文长整数
        n = self.private_key['n']
        d = self.private_key['d']
        m = pow(c, d, n)  # 解密：c^d mod n
        decrypted_bytes = long_to_bytes(m)  # 明文长整数→字节
        return decrypted_bytes.decode('utf-8')  # 字节→字符串

# ========== 3. JWT工具类（无修改，保留完整功能） ==========
class JWTService:
    def __init__(self):
        self.rsa = RSAServices()
        self.rsa.load_keys(e=65537)  # 加载RSA密钥对
        self.algorithm = "RS256"  # RSA-SHA256算法
        # 转换字典格式密钥为PEM格式（用于JWT签名/验证）
        self.pem_private_key = self._dict_to_pem_private()
        self.pem_public_key = self._dict_to_pem_public()

    def _dict_to_pem_private(self):
        """字典格式私钥→PEM格式私钥字符串"""
        try:
            # 提取RSA核心参数（n：模数，e：公钥指数，d：私钥指数）
            n = self.rsa.private_key["n"]
            e = self.rsa.private_key["e"]
            d = self.rsa.private_key["d"]
            # 构造RSA私钥对象（简化场景，完整场景需补充p、q等参数）
            key = RSA.construct((n, e, d))
            return key.export_key().decode('utf-8')  # 导出PEM格式
        except Exception as e:
            raise ValueError(f"❌ 私钥格式转换失败：{e}")

    def _dict_to_pem_public(self):
        """字典格式公钥→PEM格式公钥字符串"""
        try:
            n = self.rsa.public_key["n"]
            e = self.rsa.public_key["e"]
            # 构造RSA公钥对象
            key = RSA.construct((n, e))
            return key.export_key().decode('utf-8')  # 导出PEM格式
        except Exception as e:
            raise ValueError(f"❌ 公钥格式转换失败：{e}")

    def generate_token(self, username, role):
        """生成JWT令牌（包含访问令牌+刷新令牌）"""
        # 访问令牌：2小时有效期（用于接口访问）
        access_exp = datetime.utcnow() + timedelta(hours=2)
        access_payload = {
            "username": username,
            "role": role,
            "exp": access_exp,
            "type": "access"
        }
        access_token = jwt.encode(
            access_payload,
            self.pem_private_key,
            algorithm=self.algorithm
        )
        # 刷新令牌：7天有效期（用于刷新访问令牌）
        refresh_exp = datetime.utcnow() + timedelta(days=7)
        refresh_payload = {
            "username": username,
            "exp": refresh_exp,
            "type": "refresh"
        }
        refresh_token = jwt.encode(
            refresh_payload,
            self.pem_private_key,
            algorithm=self.algorithm
        )
        return {"access_token": access_token, "refresh_token": refresh_token}

    def verify_token(self, token):
        """验证JWT令牌（返回验证结果+ payload/错误信息）"""
        try:
            payload = jwt.decode(
                token,
                self.pem_public_key,
                algorithms=[self.algorithm]
            )
            # 仅允许访问令牌（refresh令牌不可用于接口访问）
            if payload["type"] != "access":
                return False, "❌ 无效的Token类型（仅支持access令牌）"
            return True, payload
        except jwt.ExpiredSignatureError:
            return False, "❌ Token已过期，请重新登录"
        except Exception as e:
            return False, f"❌ Token验证失败：{str(e)}"

# ========== 4. 数据模型定义（无修改，完整实体关系） ==========
class User(Base):
    __tablename__ = "users"
    username = Column(String(50), primary_key=True)  # 用户名（主键）
    password_hash = Column(String(100), nullable=False)  # 密码哈希（不存明文）
    fail_count = Column(Integer, default=0)  # 登录失败次数（防暴力破解）
    last_fail_time = Column(Float, default=0)  # 最后一次失败时间
    role = Column(String(20), nullable=False, default="buyer")  # 角色：buyer/seller/admin
    phone = Column(String(20), nullable=False)  # 明文手机号（用于内部查询）
    phone_encrypted = Column(String(200), nullable=False)  # 加密手机号（用于存储安全）

    # 关联关系
    addresses = relationship("Address", back_populates="user")
    cart = relationship("Cart", uselist=False, back_populates="user")
    orders = relationship("Order", back_populates="user")
    evaluations = relationship("Evaluation", back_populates="user")
    purchases = relationship("Purchase", back_populates="user")

class Address(Base):
    __tablename__ = "addresses"
    id = Column(Integer, primary_key=True, autoincrement=True)
    recipient = Column(String(50), nullable=False)  # 收件人
    phone = Column(String(20), nullable=False)  # 收件人手机号
    detail = Column(String(200), nullable=False)  # 详细地址
    username = Column(String(50), ForeignKey("users.username"), nullable=False)  # 关联用户

    user = relationship("User", back_populates="addresses")

class CommodityCategory(Base):
    __tablename__ = "commodity_categories"
    category_id = Column(Integer, primary_key=True, autoincrement=True)
    category_name = Column(String(50), nullable=False)  # 分类名称（如：电子产品）
    parent_id = Column(Integer, default=0)  # 父分类ID（用于多级分类，0为顶级）

    commodities = relationship("Commodity", back_populates="category")

class Manufacturer(Base):
    __tablename__ = "manufacturers"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)  # 厂商名称
    address = Column(String(200))  # 厂商地址
    phone = Column(String(20))  # 厂商联系方式

    commodities = relationship("Commodity", back_populates="manufacturer")

class Commodity(Base):
    __tablename__ = "commodities"
    name = Column(String(100), primary_key=True)  # 商品名称（主键）
    price = Column(Float, nullable=False)  # 商品价格
    stock = Column(Integer, nullable=False, default=0)  # 商品库存
    status = Column(Boolean, nullable=False, default=True)  # 状态：True（在售）/False（下架）
    category_id = Column(Integer, ForeignKey("commodity_categories.category_id"), nullable=False)  # 关联分类
    manufacturer_id = Column(Integer, ForeignKey("manufacturers.id"), nullable=False)  # 关联厂商

    category = relationship("CommodityCategory", back_populates="commodities")
    manufacturer = relationship("Manufacturer", back_populates="commodities")
    cart_items = relationship("CartItem", back_populates="commodity")
    order_items = relationship("OrderItem", back_populates="commodity")
    evaluations = relationship("Evaluation", back_populates="commodity")
    purchases = relationship("Purchase", back_populates="commodity")

class Cart(Base):
    __tablename__ = "carts"
    username = Column(String(50), ForeignKey("users.username"), primary_key=True)  # 关联用户（主键）
    create_time = Column(DateTime, default=datetime.now)  # 购物车创建时间
    item_count = Column(Integer, default=0)  # 购物车商品总数

    user = relationship("User", back_populates="cart")
    items = relationship("CartItem", back_populates="cart")

class CartItem(Base):
    __tablename__ = "cart_items"
    cart_username = Column(String(50), ForeignKey("carts.username"), primary_key=True)  # 关联购物车
    commodity_name = Column(String(100), ForeignKey("commodities.name"), primary_key=True)  # 关联商品
    quantity = Column(Integer, nullable=False, default=1)  # 商品数量
    selected = Column(Boolean, default=True)  # 是否选中（结算时用）

    cart = relationship("Cart", back_populates="items")
    commodity = relationship("Commodity", back_populates="cart_items")

class Order(Base):
    __tablename__ = "orders"
    order_number = Column(String(50), primary_key=True)  # 订单号（主键，如：202510280001）
    total_amount = Column(Float, nullable=False)  # 订单总金额
    create_time = Column(DateTime, default=datetime.now)  # 订单创建时间
    status = Column(String(20), default="待支付")  # 订单状态：待支付/已支付/已取消/已完成
    username = Column(String(50), ForeignKey("users.username"), nullable=False)  # 关联用户

    user = relationship("User", back_populates="orders")
    items = relationship("OrderItem", back_populates="order")
    evaluations = relationship("Evaluation", back_populates="order")

class OrderItem(Base):
    __tablename__ = "order_items"
    order_number = Column(String(50), ForeignKey("orders.order_number"), primary_key=True)  # 关联订单
    commodity_name = Column(String(100), ForeignKey("commodities.name"), primary_key=True)  # 关联商品
    quantity = Column(Integer, nullable=False)  # 购买数量
    price_at_purchase = Column(Float, nullable=False)  # 购买时单价（快照，避免价格变动）

    order = relationship("Order", back_populates="items")
    commodity = relationship("Commodity", back_populates="order_items")

class Evaluation(Base):
    __tablename__ = "evaluations"
    id = Column(Integer, primary_key=True, autoincrement=True)
    score = Column(Integer, nullable=False)  # 评分（1-5分）
    content = Column(Text)  # 评价内容
    time = Column(DateTime, default=datetime.now)  # 评价时间
    username = Column(String(50), ForeignKey("users.username"), nullable=False)  # 关联用户
    order_number = Column(String(50), ForeignKey("orders.order_number"), nullable=False)  # 关联订单
    commodity_name = Column(String(100), ForeignKey("commodities.name"), nullable=False)  # 关联商品

    user = relationship("User", back_populates="evaluations")
    order = relationship("Order", back_populates="evaluations")
    commodity = relationship("Commodity", back_populates="evaluations")

class Purchase(Base):
    __tablename__ = "purchases"
    username = Column(String(50), ForeignKey("users.username"), primary_key=True)  # 关联用户
    commodity_name = Column(String(100), ForeignKey("commodities.name"), primary_key=True)  # 关联商品
    purchase_time = Column(DateTime, default=datetime.now, primary_key=True)  # 购买时间（联合主键）

    user = relationship("User", back_populates="purchases")
    commodity = relationship("Commodity", back_populates="purchases")

# ========== 5. 审计日志配置（无修改） ==========
logging.basicConfig(
    filename="data_access_audit.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ========== 6. 核心业务工具函数（无修改） ==========
# 本地敏感文件配置（防止GitHub泄露）
LOCAL_DOC = "user_registry.txt"  # 本地用户信息备份文件
SENSITIVE_FILES = [LOCAL_DOC, "private_key.txt", "public_key.txt"]  # 需忽略的敏感文件

def write_to_doc(user_info):
    """将用户信息写入本地备份文件（格式：时间戳|用户名|密码哈希|加密手机号）"""
    with open(LOCAL_DOC, "a", encoding="utf-8") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        doc_line = (f"{timestamp}|{user_info['username']}|{user_info['pwd_hash']}|"
                    f"{user_info['phone_encrypted']}\n")
        f.write(doc_line)
    print(f"✅ 用户信息已备份到本地文件：{LOCAL_DOC}")

def ensure_gitignore():
    """自动配置.gitignore，忽略敏感文件（防止GitHub同步泄露）"""
    gitignore_path = ".gitignore"
    # 读取现有.gitignore内容
    existing_content = ""
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r", encoding="utf-8") as f:
            existing_content = f.read()
    # 追加缺失的敏感文件规则
    with open(gitignore_path, "a", encoding="utf-8") as f:
        for file in SENSITIVE_FILES:
            if file not in existing_content:
                f.write(f"\n# 敏感文件（自动添加，禁止同步）\n{file}")
    print(f"✅ .gitignore已配置：敏感文件{SENSITIVE_FILES}不会同步到GitHub")

def sync_to_github():
    """安全同步代码到GitHub（仅同步非敏感文件）"""
    if not os.path.exists(".git"):
        print("\n❌ 当前目录不是Git仓库，需先执行：")
        print("1. git init（初始化仓库）")
        print("2. git remote add origin <你的GitHub仓库地址>（关联远程仓库）")
        return
    # 询问用户是否同步
    sync_choice = input("\n是否将非敏感文件（代码、配置）同步到GitHub？(y/n)：").strip().lower()
    if sync_choice != "y":
        print("✅ 已取消GitHub同步")
        return
    try:
        # 暂存文件（.gitignore自动过滤敏感文件）
        subprocess.run(["git", "add", "."], check=True, capture_output=True, text=True)
        # 提交信息（含时间戳）
        commit_msg = f"Update ecommerce system: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        subprocess.run(["git", "commit", "-m", commit_msg], check=True, capture_output=True, text=True)
        # 推送到main分支（可根据实际分支修改）
        subprocess.run(["git", "push", "-u", "origin", "main"], check=True, capture_output=True, text=True)
        print("✅ GitHub同步成功：仅非敏感文件已上传")
    except subprocess.CalledProcessError as e:
        print(f"❌ GitHub同步失败：{e.stderr}")

def generate_random_string(length=32):
    """生成随机字符串（用于Session ID等场景）"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def check_username(username):
    """用户名合法性校验（6-20位，仅含字母、数字、下划线）"""
    if not 6 <= len(username) <= 20:
        return False, "❌ 用户名长度需在6-20位之间"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "❌ 用户名仅可包含字母、数字和下划线"
    return True, "✅ 用户名合法"

def check_password_strength(password):
    """密码强度校验（8位以上，含大小写、数字、特殊字符）"""
    if len(password) < 8:
        return False, "❌ 密码长度需≥8位"
    if not any(c.isupper() for c in password):
        return False, "❌ 密码需包含大写字母"
    if not any(c.islower() for c in password):
        return False, "❌ 密码需包含小写字母"
    if not any(c.isdigit() for c in password):
        return False, "❌ 密码需包含数字"
    if not any(c in "!@#$%^&*()_+{}|:\"<>?`~-=[]\\;',./" for c in password):
        return False, "❌ 密码需包含特殊字符（如!@#$%）"
    return True, "✅ 密码强度符合要求"

def check_phone(phone):
    """手机号合法性校验（中国大陆手机号格式：13-19开头，11位）"""
    if not re.match(r'^1[3-9]\d{9}$', phone):
        return False, "❌ 手机号格式不合法（需为13-19开头的11位数字）"
    return True, "✅ 手机号合法"

def hash_password(password):
    """密码哈希（使用SHA-256，避免存储明文）"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# ========== 7. 数据访问层（CRUD操作，无修改） ==========
class DAO:
    def __init__(self):
        self.db = SessionLocal()  # 创建数据库会话

    def __del__(self):
        self.db.close()  # 销毁时关闭会话

    def _audit_log(self, action, detail):
        """记录审计日志（关键操作可追溯）"""
        logger.info(f"Action: {action}, Detail: {detail}")

    # ---------- 用户相关操作 ----------
    def get_user_by_username(self, username):
        """根据用户名查询用户信息"""
        user = self.db.query(User).filter(User.username == username).first()
        self._audit_log("QUERY_USER", f"Username: {username}")
        return user

    def create_user(self, user_info):
        """创建新用户（用户信息含：username、pwd_hash、phone、phone_encrypted、role）"""
        new_user = User(
            username=user_info["username"],
            password_hash=user_info["pwd_hash"],
            phone=user_info["phone"],
            phone_encrypted=user_info["phone_encrypted"],
            role=user_info.get("role", "buyer")  # 默认角色为普通买家
        )
        self.db.add(new_user)
        self.db.commit()
        self._audit_log("CREATE_USER", f"Username: {user_info['username']}")
        return new_user

    def update_user_fail_count(self, username, fail_count, last_fail_time):
        """更新用户登录失败次数和时间（防暴力破解）"""
        user = self.get_user_by_username(username)
        if user:
            user.fail_count = fail_count
            user.last_fail_time = last_fail_time
            self.db.commit()
            self._audit_log("UPDATE_USER_FAIL_COUNT", f"Username: {username}, Fail Count: {fail_count}")
            return True
        return False

    # ---------- 商品相关操作 ----------
    def get_commodity_by_name(self, name):
        """根据商品名称查询商品信息"""
        commodity = self.db.query(Commodity).filter(Commodity.name == name).first()
        self._audit_log("QUERY_COMMODITY", f"Commodity Name: {name}")
        return commodity

    def update_commodity_stock(self, name, quantity_change):
        """更新商品库存（quantity_change为正数表示增加，负数表示减少）"""
        commodity = self.get_commodity_by_name(name)
        if commodity:
            # 确保库存不小于0
            if commodity.stock + quantity_change < 0:
                raise ValueError(f"❌ 库存不足：当前库存{commodity.stock}，需减少{abs(quantity_change)}")
            commodity.stock += quantity_change
            self.db.commit()
            self._audit_log("UPDATE_COMMODITY_STOCK", 
                           f"Commodity: {name}, Stock Change: {quantity_change}, New Stock: {commodity.stock}")
            return True
        return False

    # ---------- 订单相关操作 ----------
    def create_order(self, order_info, order_items):
        """创建订单（含订单主信息和订单商品明细）"""
        # 创建订单主记录
        new_order = Order(
            order_number=order_info["order_number"],
            total_amount=order_info["total_amount"],
            username=order_info["username"],
            status=order_info.get("status", "待支付")
        )
        self.db.add(new_order)
        # 创建订单商品明细
        for item in order_items:
            order_item = OrderItem(
                order_number=order_info["order_number"],
                commodity_name=item["commodity_name"],
                quantity=item["quantity"],
                price_at_purchase=item["price_at_purchase"]
            )
            self.db.add(order_item)
            # 扣减商品库存
            self.update_commodity_stock(item["commodity_name"], -item["quantity"])
        self.db.commit()
        self._audit_log("CREATE_ORDER", 
                       f"Order Number: {order_info['order_number']}, Total Amount: {order_info['total_amount']}")
        return new_order

# ========== 8. 业务功能（注册/登录，无修改） ==========
def register():
    """用户注册流程：输入校验→RSA加密→数据库存储→本地备份→GitHub同步"""
    print("\n=== 用户注册 ===")
    # 1. 输入并校验用户名
    username = input("请输入用户名：")
    username_valid, username_msg = check_username(username)
    if not username_valid:
        print(username_msg)
        return
    # 检查用户名是否已存在
    dao = DAO()
    if dao.get_user_by_username(username):
        print("❌ 用户名已存在，请更换用户名")
        return

    # 2. 输入并校验密码
    password = input("请输入密码：")
    pwd_valid, pwd_msg = check_password_strength(password)
    if not pwd_valid:
        print(pwd_msg)
        return
    password_hash = hash_password(password)  # 密码哈希处理

    # 3. 输入并校验手机号
    phone = input("请输入手机号：")
    phone_valid, phone_msg = check_phone(phone)
    if not phone_valid:
        print(phone_msg)
        return

    # 4. RSA加密手机号（敏感信息保护）
    rsa_service = RSAServices()
    rsa_service.load_keys(e=65537)
    try:
        encrypted_phone = rsa_service.encrypt(phone)
        print(f"✅ 手机号加密完成：{encrypted_phone[:30]}...")  # 脱敏显示
    except Exception as e:
        print(f"❌ 手机号加密失败：{e}")
        return

    # 5. 存储用户信息（数据库+本地备份）
    user_info = {
        "username": username,
        "pwd_hash": password_hash,
        "phone": phone,
        "phone_encrypted": encrypted_phone,
        "role": "buyer"  # 默认注册为普通买家
    }
    # 写入数据库
    dao.create_user(user_info)
    print("✅ 用户信息已写入数据库")
    # 写入本地备份文件
    write_to_doc(user_info)

    # 6. GitHub同步提示
    sync_to_github()

def login():
    """用户登录流程：用户查询→密码校验→防暴力破解→JWT令牌生成→权限展示"""
    print("\n=== 用户登录 ===")
    username = input("请输入用户名：")
    password = input("请输入密码：")
    dao = DAO()
    jwt_service = JWTService()

    # 1. 查询用户信息
    user = dao.get_user_by_username(username)
    if not user:
        print("❌ 用户名不存在")
        return

    # 2. 防暴力破解：失败5次锁定1小时
    if user.fail_count >= 5:
        lock_remaining = 3600 - (time.time() - user.last_fail_time)
        if lock_remaining > 0:
            print(f"❌ 账户已锁定，剩余{int(lock_remaining)}秒后可重试")
            return
        else:
            # 锁定时间过后，重置失败次数
            dao.update_user_fail_count(username, 0, 0)
            print("✅ 账户锁定已解除，可正常登录")

    # 3. 密码校验（比对哈希值，不处理明文）
    input_password_hash = hash_password(password)
    if input_password_hash != user.password_hash:
        new_fail_count = user.fail_count + 1
        dao.update_user_fail_count(username, new_fail_count, time.time())
        print(f"❌ 密码错误，剩余尝试次数：{5 - new_fail_count}")
        return

    # 4. 登录成功：重置失败次数+生成JWT令牌
    dao.update_user_fail_count(username, 0, 0)
    print("✅ 登录成功！")
    # 生成JWT令牌
    tokens = jwt_service.generate_token(username, user.role)
    print("\n📌 JWT令牌信息（脱敏显示）：")
    print(f"访问令牌（2小时有效）：{tokens['access_token'][:40]}...")
    print(f"刷新令牌（7天有效）：{tokens['refresh_token'][:40]}...")

    # 5. 验证令牌并展示角色权限
    verify_ok, result = jwt_service.verify_token(tokens['access_token'])
    if verify_ok:
        print(f"\n🔍 当前用户信息：")
        print(f"用户名：{result['username']}")
        print(f"角色：{result['role']}")
        # 角色权限说明
        if result['role'] == "admin":
            print("📊 权限：管理所有用户、商品、订单")
        elif result['role'] == "seller":
            print("🏪 权限：管理自有商品、店铺、订单")
        else:
            print("🛒 权限：浏览商品、加入购物车、下单、评价")
    else:
        print(f"❌ Token验证失败：{result}")

# ========== 9. 数据库初始化与主程序（无修改） ==========
def init_db():
    """初始化数据库（首次运行时执行，创建所有表结构）"""
    Base.metadata.create_all(bind=engine)
    print("✅ 数据库表结构初始化完成")

if __name__ == "__main__":
    # 1. 初始化数据库（首次运行时取消注释执行）
    # init_db()

    # 2. 确保.gitignore配置（防止敏感文件泄露）
    ensure_gitignore()

    # 3. 主菜单循环
    while True:
        print("\n=== 电子商务系统用户管理 ===")
        print("1. 用户注册（自动加密敏感信息+本地备份）")
        print("2. 用户登录（生成JWT令牌+角色权限展示）")
        print("3. 退出系统")
        choice = input("请选择操作（1/2/3）：")
        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            print("感谢使用，再见！")
            break
        else:
            print("❌ 无效选择，请输入1、2或3")
