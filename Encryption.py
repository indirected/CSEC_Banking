from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
class AESCrypto:
    def __init__(self, key):
        self.__key = key
        self.__blocksize = AES.block_size
    
    def __pad(self, s):
        return s + (self.__blocksize - len(s) % self.__blocksize) * chr(self.__blocksize - len(s) % self.__blocksize)
    
    def __unpad(self, s):
        return s[:-ord(s[-1])]
    
    def encrypt(self, plain: str) -> bytes:
        plain = self.__pad(plain)
        iv = get_random_bytes(self.__blocksize)
        Cryptor = AES.new(self.__key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + Cryptor.encrypt(plain.encode('ascii')))
    
    def decrypt(self, cipher: bytes) -> str:
        cipher = base64.b64decode(cipher)
        iv = cipher[0:self.__blocksize]
        Cryptor = AES.new(self.__key, AES.MODE_CBC, iv)
        return self.__unpad(Cryptor.decrypt(cipher[self.__blocksize:]).decode('ascii'))