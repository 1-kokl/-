import random
from Crypto.Util.number import bytes_to_long, long_to_bytes
import base64
import json
def serialize(info):
    if isinstance(info,(list,dict)):
        json_list = json.dumps(info)
        return base64.b64encode(json_list.encode()).decode()

def deserialize(serialize_data):
    try:
        json_list = base64.b64decode(serialize_data.encode())
        return json.loads(json_list.decode("utf-8"))
    except Exception as e:
        print("反序列化失败")
        raise

def is_prime(n):
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

def get_prime(bits):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1
        if is_prime(p):
            return p
def gra_pra_pub_key(e= 65537) :
    p = get_prime(1024)
    q = get_prime(1024)
    n = p*q
    phi_n = (p-1)*(q-1)
    d = pow(e,-1,phi_n)
    private_key= {
        "type" : "private",
        "n" : n,
        "d" : d,
        'e': e,
        "key_size": 1024
    }
    public_key = {
        "type" : "public",
        "n" : n,
        "e" : e,
        "key_size": 1024
    }
    return private_key,public_key


def rsa_encrypt(public_key, info):
    if not isinstance(info, str):
        info = str(info)

    m = bytes_to_long(info.encode('utf-8'))
    n = public_key['n']
    e = public_key['e']

    max_length = (public_key['key_size'] // 8) - 11
    if len(info.encode('utf-8')) > max_length:
        raise ValueError(f"数据过长，最大支持{max_length}字节")
    c = pow(m, e, n)
    encrypted_bytes = long_to_bytes(c)
    return base64.b64encode(encrypted_bytes).decode('utf-8')
def rsa_decrypt(private_key, encrypted_data):

    encrypted_bytes = base64.b64decode(encrypted_data)
    c = bytes_to_long(encrypted_bytes)

    n = private_key['n']
    d = private_key['d']

    m = pow(c, d, n)

    decrypted_bytes = long_to_bytes(m)
    return decrypted_bytes.decode('utf-8')


class  RSAServices :
    def __init__(self):
        self.path = "RSA_crypto.py"
        self.private_key = None
        self.public_key = None
        self.size = None

    def load_keys(self,e):
        try:
            with open("private_key.txt","r",encoding="utf-8") as f:
                self.private_key = deserialize(f.read())
                print("私钥加载完毕")
            with open("public_key.txt","r",encoding="utf-8") as f:
                self.public_key = deserialize(f.read())
                print("公钥加载完毕")
            print(self.public_key,"##",self.private_key)
        except Exception as e:
            print("密钥对加载失败")
            self.generate_keys()

    def generate_keys(self):
        self.private_key, self.public_key = gra_pra_pub_key(65537)

        with open("private_key.txt","w",encoding="utf-8") as f :
                serialize_private = serialize(self.private_key)
                f.write(serialize_private)

        with open("public_key.txt","w",encoding="utf-8") as f:
                serialize_public = serialize(self.public_key)
                f.write(serialize_public)
        print("已生成并保存保存钥匙对")

    def encrypt(self, info):
        if self.public_key is None:
            raise RuntimeError("公钥未初始化")

        return rsa_encrypt(self.public_key, info)

    def decrypt(self, encrypted_data):
        if self.private_key is None:
            raise RuntimeError("私钥未初始化")

        return rsa_decrypt(self.private_key, encrypted_data)


