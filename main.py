from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pkcs7 import PKCS7Encoder
import base64


BLOCK_CHUNK = 16

def pkcs7_pad(data: bytes, block_size: int = BLOCK_CHUNK) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int = BLOCK_CHUNK) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Неверная длина дополненного сообщения")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Неверное значение паддинга")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Неверное дополнение (PKCS7)")
    return data[:-pad_len]

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
        self.c_ecb = AES.new(key, AES.MODE_ECB)
        self.last_block_e = None
        self.last_block_d = None
        
    def SetMode(self, mode):
        if (mode not in ["ECB", "CBC", "CFB", "OFB", "CTR"]):
            raise Exception("Invalid mode")
        
        self.mode = mode
        self.last_block_e = None
        self.last_block_d = None

    """def pkcs7_encode(self, data):
        pkcs7 = PKCS7Encoder(BLOCK_CHUNK)
        return pkcs7.encode(data)
    
    def pkcs7_decode(self, data):
        pkcs7 = PKCS7Encoder(BLOCK_CHUNK)
        return pkcs7.decode(data)
    """
    def m_xor(self, data1, data2):
        return bytes(x ^ y for x, y in zip(data1, data2))
    
    #check of working
    def increment(cnt):
        counter = int.from_bytes(counter, byteorder="big")
        counter = (counter + 1) % (1 << (len(cnt) * 8))
        return counter.to_bytes(len(cnt), byteorder="big")

    def BlockCipherEncrypt(self, data):
        if (len(data) != BLOCK_CHUNK):
            raise Exception("Invalid data length")
        
        return self.c_ecb.encrypt(data)
    
    def BlockCipherDecrypt(self, data):
        if (len(data) != BLOCK_CHUNK):
            raise Exception("Invalid data length")
        
        return self.c_ecb.decrypt(data)
    
    def ProcessBlockEncrypt(self, data, isFinalBlock, padding):

        if (self.mode == "ECB"):
            if (isFinalBlock):
                pad = pkcs7_pad(data) if (padding == "PKCS7") else data
                res = b""
                for i in range(0, len(pad), BLOCK_CHUNK):
                    block = pad[i: i + BLOCK_CHUNK]
                    res += self.BlockCipherEncrypt(block)
                return res

            else:
                return self.BlockCipherEncrypt(data)
        
        if (self.mode == "CBC"):
            if (self.last_block_e == None):
                self.last_block_e = get_random_bytes(BLOCK_CHUNK)
            
            res = b""
            # check in here
            if (isFinalBlock):
                pad = pkcs7_pad(data) if (padding == "PKCS7") else data
                
            else:
                pad = data
            for i in range(0, len(pad), BLOCK_CHUNK):
                    block = pad[i: i + BLOCK_CHUNK]
                    xor = self.m_xor(block, self.last_block_e)
                    enc = self.BlockCipherEncrypt(xor)
                    res += enc
                    self.last_block_e = enc    
            return res
                

        if (self.mode == "CFB"):
            if (self.last_block_e == None):
                self.last_block_e = get_random_bytes(BLOCK_CHUNK)

            keyIv = self.BlockCipherEncrypt(self.last_block_e)
            cipherText = self.m_xor(data, keyIv[:len(data)])

            # check in here !!!
            if (isFinalBlock):
                self.last_block_e = cipherText + self.last_block_e[len(data):]
            else: 
                self.last_block_e = cipherText 
            return cipherText
            
        if (self.mode == "OFB"):
            if (self.last_block_e == None):
                self.last_block_e = get_random_bytes(BLOCK_CHUNK)
            keyIv = self.BlockCipherEncrypt(self.last_block_e)
            self.last_block_e = keyIv
            return self.m_xor(data, keyIv[:len(data)])

        # need to compare with details
        if (self.mode == "CTR"):
            if (self.last_block_e == None):
                self.last_block_e = get_random_bytes(BLOCK_CHUNK)
            keyIv = self.BlockCipherEncrypt(self.last_block_e)
            out = self.m_xor(data, keyIv[:len(data)])
            self.last_block_e = self.increment(self.last_block_e)
            return out

    def ProcessBlockDecrypt(self, data, isFinalBlock, padding):
        if (self.last_block_d == None):
            self.last_block_d = data
            return b""
        
        if (self.mode == "ECB"):
            res = b""
            if (isFinalBlock):
                for i in range(0, len(data), BLOCK_CHUNK):
                    block = data[i:i + BLOCK_CHUNK]
                    res += self.BlockCipherDecrypt(block)
                if (padding == "PKCS7"):
                    res = pkcs7_unpad(res)
                return res 
            else: 
                return self.BlockCipherDecrypt(data)

        if (self.mode == "CBC"):
            res = b""
            if (isFinalBlock):
                for i in range(0, len(data), BLOCK_CHUNK):
                    block = data[i:i + BLOCK_CHUNK]
                    decode = self.BlockCipherDecrypt(block)
                    plain = self.m_xor(decode, self.last_block_d)
                    res += plain
                    self.last_block_d = block
                if (padding == "PKCS7"):
                    res = pkcs7_unpad(res)
                return res
            else:
                decode = self.BlockCipherDecrypt(data)
                plain = self.m_xor(decode, self.last_block_d)
                self.last_block_d = data
                return plain
            
        if (self.mode == "CFB"):
            if (self.last_block_d == None):
                self.last_block_d = data
                return b""
            decode = self.BlockCipherDecrypt(self.last_block_d)
            decode = self.m_xor(data, decode[:len(data)])
            if (len(data) < BLOCK_CHUNK):
                self.last_block_d = self.last_block_d[len(data):] + data
            else:
                self.last_block_d = data
            return decode
        
        if (self.mode == "OFB"):
            if (self.last_block_d is None):
                self.last_block_d = data
                return b""
            decode = self.BlockCipherDecrypt(self.last_block_d)
            self.last_block_d = decode
            return self.m_xor(data, decode[:len(data)])

        if (self.mode == "CTR"):
            if (self.last_block_d is None):
                self.last_block_d = data
                return b""
            decode = self.BlockCipherDecrypt(self.last_block_d)
            self.last_block_d = self.increment(self.last_block_d)
            return self.m_xor(data, decode[:len(data)])

    def Encrypt(self, data, iv = None):
        self.last_block_e = None
        self.last_block_d = None
        res = b""

        if (self.mode in ["CBC", "CFB", "OFB", "CTR"]):
            if (iv is None or len(iv) != BLOCK_CHUNK):
                iv = get_random_bytes(BLOCK_CHUNK)
            self.last_block_e = iv
            res += iv
        
        if (self.mode in ["ECB", "CBC"]):
            padding = "PKCS7"
        else:
            padding = "NON"
        
        arr_of_blocks = [data[i:i+BLOCK_CHUNK] for i in range(0, len(data), BLOCK_CHUNK)]

        for b in arr_of_blocks[:-1]:
            if len(b) != BLOCK_CHUNK:
                res += self.ProcessBlockEncrypt(b, True, padding)
            else:
                res += self.ProcessBlockEncrypt(b, False, padding)
        res += self.ProcessBlockEncrypt(arr_of_blocks[-1], True, padding)
        return res
    
    def Decrypt(self, data, iv = None):
        self.last_block_d = None
        self.last_block_e = None
        res = b""
        if (self.mode in ["CBC", "CFB", "OFB", "CTR"]):
            if (iv == None or len(iv) != BLOCK_CHUNK):
                iv = data[:BLOCK_CHUNK]
                data = data[BLOCK_CHUNK:]
            self.last_block_d = iv
        
        if (self.mode in ["ECB", "CBC"]):
            padding = "PKCS7"
        else:
            padding = "NON"

        arr_of_blocks = [data[i:i+BLOCK_CHUNK] for i in range(0, len(data), BLOCK_CHUNK)]
        if not arr_of_blocks:
            return b""
        for b in arr_of_blocks[:-1]:
            if len(b) != BLOCK_CHUNK:
                raise ValueError("Непоследовательный блок должен быть 16 байт")
            res += self.ProcessBlockDecrypt(b, False, padding)
        res += self.ProcessBlockDecrypt(arr_of_blocks[-1], True, padding)
        return res
        
if __name__ == '__main__':
    import binascii

    # Пример: расшифровка шифртекста CBC (PKCS7 padding, ASCII)
    cbc_key = binascii.unhexlify("140b41b22a29beb4061bda66b6747e14")
    cbc_ct1 = binascii.unhexlify(
        "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee"
        "2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81")
    cipher = AESHandler()
    cipher.SetKey(cbc_key)
    cipher.SetMode("CBC")
    pt1 = cipher.Decrypt(cbc_ct1)
    print("CBC ciphertext 1 ->", pt1.decode('ascii'))

    cbc_ct2 = binascii.unhexlify(
        "5b68629feb8606f9a6667670b75b38a5"
        "b4832d0f26e1ab7da33249de7d4afc48"
        "e713ac646ace36e872ad5fb8a512428a"
        "6e21364b0c374df45503473c5242a253")
    cipher.SetKey(cbc_key)
    cipher.SetMode("CBC")
    pt2 = cipher.Decrypt(cbc_ct2)
    print("CBC ciphertext 2 ->", pt2.decode('ascii'))
