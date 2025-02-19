from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


BLOCK_CHUNK = 16


class AESHandler():
    def __init__(self, key=None, mode=None, c_ecb = None, last_block_e = None, last_block_d = None):
        self.key = key
        self.mode = mode
        self.c_ecb = c_ecb
        self.last_block_e = last_block_e # encryption
        self.last_block_d = last_block_d # decryption

    def SetKey(self, key):
        if (len(key) != BLOCK_CHUNK):
            raise Exception("Invalid key length")
        
        self.key = key
        self.last_block_e = None
        self.last_block_d = None
        self.c_ecb = AES.new(key, AES.MODE_ECB)

    def SetMode(self, mode):
        if (mode not in ["ECB", "CBC", "CFB", "OFB", "CTR"]):
            raise Exception("Invalid mode")
        
        self.mode = mode
        self.last_block_e = None
        self.last_block_d = None

    def BlockCypherEncrypt(self, data):
        if (len(data) != BLOCK_CHUNK):
            raise Exception("Invalid data length")
        
        return self.c_ecb.encrypt(data)
    
    def BlockCypherDecrypt(self, data):
        if (len(data) != BLOCK_CHUNK):
            raise Exception("Invalid data length")
        
        return self.c_ecb.decrypt(data)
    
    def ProcessBlockEncrypt(self, data, isFinalBlock, padding):

        if (self.mode is "ECB"):
        
        if (self.mode is "CBC"):

        if (self.mode is "CFB"):

        if (self.mode is "OFB"):

        if (self.mode is "CTR"):

    def ProcessBlockEncrypt(self, data, isFinalBlock, padding):

        if (self.mode is "ECB"):
        
        if (self.mode is "CBC"):

        if (self.mode is "CFB"):

        if (self.mode is "OFB"):

        if (self.mode is "CTR"):

    def Encrypt(self, data, iv = None):
        self.last_block_e = None
        self.last_block_d = None
        res = b""

        if (self.mode in ["CBC", "CFB", "OFB", "CTR"] and (iv is None or len(iv) != BLOCK_CHUNK)):
            iv = get_random_bytes(BLOCK_CHUNK)
            self.last_block_e = iv
            res += iv
        
        if (self.mode in ["ECB", "CBC"]):
            padding = "PKCS7"
        else:
            padding = "NON"
        
        arr_of_blocks = [data[i:i+BLOCK_CHUNK] for i in range(0, len(data), BLOCK_CHUNK)]

        for block in arr_of_blocks:
            if (len(block) < BLOCK_CHUNK or arr_of_blocks[-1] is block):
                res += self.BlockCypherEncrypt(block, True, padding)
            else:
                res += self.BlockCypherEncrypt(block, False, padding)
        
        return res

        
    
    def Decrypt(data, iv = None):
