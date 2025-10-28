from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base  # 调整后的导入
from sqlalchemy.orm import sessionmaker, relationship
import logging
from datetime import datetime

# ========== 1. 连接池与引擎配置 ==========
engine = create_engine(
    "sqlite:///ecommerce.db",  # 连接本地SQLite数据库文件
    pool_size=10,  # 连接池大小
    max_overflow=20,  # 最大溢出连接数
    pool_timeout=30,  # 连接超时时间
    pool_recycle=3600  # 连接回收时间
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()  # 使用新导入创建Base

# ========== 2. 数据模型定义（对应实验6的实体关系） ==========
class User(Base):
    __tablename__ = "user"
    username = Column(String(50), primary_key=True)
    phone = Column(String(20), nullable=False)
    password = Column(String(100), nullable=False)
    
    addresses = relationship("Address", back_populates="user")
    cart = relationship("Cart", uselist=False, back_populates="user")
    orders = relationship("Order", back_populates="user")
    evaluations = relationship("Evaluation", back_populates="user")
    purchases = relationship("Purchase", back_populates="user")

class Address(Base):
    __tablename__ = "address"
    id = Column(Integer, primary_key=True, autoincrement=True)
    recipient = Column(String(50), nullable=False)
    phone = Column(String(20), nullable=False)
    detail = Column(String(200), nullable=False)
    username = Column(String(50), ForeignKey("user.username"), nullable=False)
    
    user = relationship("User", back_populates="addresses")

class CommodityCategory(Base):
    __tablename__ = "commodity_category"
    category_id = Column(Integer, primary_key=True, autoincrement=True)
    category_name = Column(String(50), nullable=False)
    parent_id = Column(Integer)  # 父分类ID，用于多级分类
    
    commodities = relationship("Commodity", back_populates="category")

class Manufacturer(Base):
    __tablename__ = "manufacturer"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(22), nullable=False)
    address = Column(String(60))
    phone = Column(String(20))
    
    commodities = relationship("Commodity", back_populates="manufacturer")

class Commodity(Base):
    __tablename__ = "commodity"
    name = Column(String(100), primary_key=True)
    price = Column(Float, nullable=False)
    stock = Column(Integer, nullable=False, default=0)
    status = Column(Boolean, nullable=False, default=True)  # 商品状态：1-在售，0-下架
    category_id = Column(Integer, ForeignKey("commodity_category.category_id"), nullable=False)
    manufacturer_id = Column(Integer, ForeignKey("manufacturer.id"), nullable=False)
    
    category = relationship("CommodityCategory", back_populates="commodities")
    manufacturer = relationship("Manufacturer", back_populates="commodities")
    cart_items = relationship("CartItem", back_populates="commodity")
    order_items = relationship("OrderItem", back_populates="commodity")
    evaluations = relationship("Evaluation", back_populates="commodity")
    purchases = relationship("Purchase", back_populates="commodity")

class Cart(Base):
    __tablename__ = "cart"
    username = Column(String(50), ForeignKey("user.username"), primary_key=True)
    create_time = Column(DateTime, default=datetime.now)
    item_count = Column(Integer, default=0)
    
    user = relationship("User", back_populates="cart")
    items = relationship("CartItem", back_populates="cart")

class CartItem(Base):
    __tablename__ = "cart_item"
    cart_username = Column(String(50), ForeignKey("cart.username"), primary_key=True)
    commodity_name = Column(String(100), ForeignKey("commodity.name"), primary_key=True)
    quantity = Column(Integer, nullable=False, default=1)
    selected = Column(Boolean, default=True)
    
    cart = relationship("Cart", back_populates="items")
    commodity = relationship("Commodity", back_populates="cart_items")

class Order(Base):
    __tablename__ = "order"
    order_number = Column(String(50), primary_key=True)
    total_amount = Column(Float, nullable=False)
    create_time = Column(DateTime, default=datetime.now)
    status = Column(String(20), default="待支付")
    username = Column(String(50), ForeignKey("user.username"), nullable=False)
    
    user = relationship("User", back_populates="orders")
    items = relationship("OrderItem", back_populates="order")
    evaluations = relationship("Evaluation", back_populates="order")

class OrderItem(Base):
    __tablename__ = "order_item"
    order_number = Column(String(50), ForeignKey("order.order_number"), primary_key=True)
    commodity_name = Column(String(100), ForeignKey("commodity.name"), primary_key=True)
    quantity = Column(Integer, nullable=False)
    price_at_purchase = Column(Float, nullable=False)  # 购买时的价格
    
    order = relationship("Order", back_populates="items")
    commodity = relationship("Commodity", back_populates="order_items")

class Evaluation(Base):
    __tablename__ = "evaluation"
    id = Column(Integer, primary_key=True, autoincrement=True)
    score = Column(Integer, nullable=False)
    content = Column(Text)
    time = Column(DateTime, default=datetime.now)
    username = Column(String(30), ForeignKey("user.username"), nullable=False)
    order_number = Column(String(50), ForeignKey("order.order_number"), nullable=False)
    commodity_name = Column(String(100), ForeignKey("commodity.name"), nullable=False)
    
    user = relationship("User", back_populates="evaluations")
    order = relationship("Order", back_populates="evaluations")
    commodity = relationship("Commodity", back_populates="evaluations")

class Purchase(Base):
    __tablename__ = "purchase"
    username = Column(String(50), ForeignKey("user.username"), primary_key=True)
    commodity_name = Column(String(100), ForeignKey("commodity.name"), primary_key=True)
    purchase_time = Column(DateTime, default=datetime.now, primary_key=True)
    
    user = relationship("User", back_populates="purchases")
    commodity = relationship("Commodity", back_populates="purchases")

# ========== 3. 审计日志配置（记录关键操作） ==========
logging.basicConfig(
    filename="data_access_audit.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ========== 4. 数据访问层核心方法（CRUD + 安全校验） ==========
class DAO:
    def __init__(self):
        self.db = SessionLocal()
    
    def __del__(self):
        self.db.close()
    
    def _audit_log(self, action, detail):
        """记录审计日志"""
        logger.info(f"Action: {action}, Detail: {detail}")
    
    # ---------- 用户模块 ----------
    def get_user(self, username):
        user = self.db.query(User).filter(User.username == username).first()
        self._audit_log("QUERY_USER", f"Username: {username}")
        return user
    
    def create_user(self, username, phone, password):
        new_user = User(username=username, phone=phone, password=password)
        self.db.add(new_user)
        self.db.commit()
        self._audit_log("CREATE_USER", f"Username: {username}")
        return new_user
    
    # ---------- 商品模块 ----------
    def get_commodity(self, name):
        """防注入：通过ORM参数化查询，避免SQL注入"""
        commodity = self.db.query(Commodity).filter(Commodity.name == name).first()
        self._audit_log("QUERY_COMMODITY", f"Commodity Name: {name}")
        return commodity
    
    def update_commodity_stock(self, name, quantity):
        """更新商品库存（下单、退款等场景使用）"""
        commodity = self.db.query(Commodity).filter(Commodity.name == name).first()
        if commodity:
            commodity.stock += quantity
            self.db.commit()
            self._audit_log("UPDATE_COMMODITY_STOCK", f"Commodity: {name}, Stock Change: {quantity}")
            return True
        return False
    
    # ---------- 订单模块 ----------
    def create_order(self, order_number, total_amount, username, items):
        """创建订单，包含订单商品明细"""
        new_order = Order(
            order_number=order_number,
            total_amount=total_amount,
            username=username
        )
        self.db.add(new_order)
        for item in items:
            order_item = OrderItem(
                order_number=order_number,
                commodity_name=item["commodity_name"],
                quantity=item["quantity"],
                price_at_purchase=item["price"]
            )
            self.db.add(order_item)
            # 扣减商品库存
            self.update_commodity_stock(item["commodity_name"], -item["quantity"])
        self.db.commit()
        self._audit_log("CREATE_ORDER", f"Order Number: {order_number}, Total: {total_amount}")
        return new_order

# ========== 5. 初始化数据库（首次运行时执行） ==========
def init_db():
    Base.metadata.create_all(bind=engine)
    print("数据库表结构初始化完成")

# ========== 测试示例 ==========
if __name__ == "__main__":
    # 初始化数据库（仅首次执行）
    # init_db()
    
    # 实例化数据访问对象
    dao = DAO()
    
    # 示例：创建用户
    # dao.create_user("test_user", "13800138000", "hashed_password")
    
    # 示例：查询商品
    # commodity = dao.get_commodity("测试商品")
    # print(commodity.name, commodity.price, commodity.stock)
