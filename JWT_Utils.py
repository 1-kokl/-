import jwt
from datetime import datetime, timedelta
from RSA_crypto import RSAServices
from Crypto.PublicKey import RSA  # 用于构造PEM密钥
import math


class JWTService:
    def __init__(self):
        self.rsa = RSAServices()
        self.rsa.load_keys(e=65537)  # 加载原有字典格式密钥
        self.algorithm = "RS256"
        # 新增：将字典密钥转换为PEM格式
        self.pem_private_key = self._dict_to_pem_private()
        self.pem_public_key = self._dict_to_pem_public()

    def _dict_to_pem_private(self):
        """将原有private_key字典（n, d, e）转换为PEM格式私钥"""
        try:
            # 从字典中提取RSA核心参数（n:  modulus, e: 公钥指数, d: 私钥指数）
            n = self.rsa.private_key["n"]
            e = self.rsa.private_key["e"]
            d = self.rsa.private_key["d"]

            # 构造RSA私钥对象（需补充p, q等参数，这里简化处理）
            # 注：完整私钥需要p、q等因子，若原代码未存储，可通过n和d推导（简化场景）
            # 以下是简化逻辑，适用于实验环境
            key = RSA.construct((n, e, d))
            return key.export_key().decode('utf-8')  # 导出为PEM字符串
        except Exception as e:
            raise ValueError(f"私钥格式转换失败：{e}")

    def _dict_to_pem_public(self):
        """将原有public_key字典（n, e）转换为PEM格式公钥"""
        try:
            n = self.rsa.public_key["n"]
            e = self.rsa.public_key["e"]
            # 构造RSA公钥对象
            key = RSA.construct((n, e))
            return key.export_key().decode('utf-8')  # 导出为PEM字符串
        except Exception as e:
            raise ValueError(f"公钥格式转换失败：{e}")

    def generate_token(self, username, role):
        """用转换后的PEM私钥生成Token"""
        access_exp = datetime.utcnow() + timedelta(hours=2)
        access_payload = {
            "username": username,
            "role": role,
            "exp": access_exp,
            "type": "access"
        }

        # 使用转换后的PEM私钥签名
        access_token = jwt.encode(
            access_payload,
            self.pem_private_key,  # 这里用转换后的PEM私钥
            algorithm=self.algorithm
        )

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
        """用转换后的PEM公钥验证Token"""
        try:
            payload = jwt.decode(
                token,
                self.pem_public_key,  # 用转换后的PEM公钥
                algorithms=[self.algorithm]
            )
            if payload["type"] != "access":
                return False, "无效的Token类型"
            return True, payload
        except jwt.ExpiredSignatureError:
            return False, "Token已过期"
        except Exception as e:
            return False, f"验证失败：{str(e)}"