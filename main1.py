from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pkcs7 import PKCS7Encoder
import binascii
from Crypto.Cipher import AES as PyCryptoAES
import base64
from Crypto.Util.Padding import pad, unpad

BLOCK_CHUNK = 16

class AESHandler():
    def __init__(self, key=None, mode=None, c_ecb=None, last_block_e=None, last_block_d=None):
        self.key = key
        self.mode = mode
        self.c_ecb = c_ecb
        self.last_block_e = last_block_e  # encryption
        self.last_block_d = last_block_d  # decryption

    def SetKey(self, key):
        if len(key) != BLOCK_CHUNK:
            raise Exception("Invalid key length")

        self.key = key
        self.c_ecb = AES.new(key, AES.MODE_ECB)
        self.last_block_e = None
        self.last_block_d = None

    def SetMode(self, mode):
        if mode not in ["ECB", "CBC", "CFB", "OFB", "CTR"]:
            raise Exception("Invalid mode")

        self.mode = mode
        self.last_block_e = None
        self.last_block_d = None

    def pkcs7_pad(self, data, block_size=BLOCK_CHUNK):
        return pad(data, block_size)

    def pkcs7_unpad(self, data, block_size=BLOCK_CHUNK):
        return unpad(data, block_size)

    def m_xor(self, data1, data2):
        return bytes(x ^ y for x, y in zip(data1, data2))

    def increment(self, cnt):
        counter = int.from_bytes(cnt, byteorder="big")
        counter = (counter + 1) % (1 << (len(cnt) * 8))
        return counter.to_bytes(len(cnt), byteorder="big")


    def BlockCipherEncrypt(self, data):
        return self.c_ecb.encrypt(data)

    def BlockCipherDecrypt(self, data):
        return self.c_ecb.decrypt(data)

    def ProcessBlockEncrypt(self, data, isFinal, padding):
        if (self.mode == "ECB"):
            pad = self.pkcs7_pad(data, BLOCK_CHUNK) if (padding == "PKCS7" and isFinal) else data
            return self.BlockCipherEncrypt(pad)

        if (self.mode == "CBC"):
            if isFinal:
                data = self.pkcs7_pad(data)
            tmp = self.m_xor(data, self.last_block_e)
            encrypted = self.BlockCipherEncrypt(tmp)
            self.last_block_e = encrypted
            return encrypted
        
        if (self.mode == "CFB"):
            tmp = self.BlockCipherEncrypt(self.last_block_e)
            encrypted = self.m_xor(data, tmp)
            self.last_block_e = encrypted
            return encrypted
        
        if (self.mode == "OFB"):
            tmp = self.BlockCipherEncrypt(self.last_block_e)
            self.last_block_e = tmp
            encrypted = self.m_xor(tmp, data)
            return encrypted
        
        if (self.mode == "CTR"):
            tmp = self.BlockCipherEncrypt(self.last_block_e)
            encrypted = self.m_xor(data, tmp)
            self.last_block_e = self.increment(self.last_block_e)
            return encrypted
        
        """if (self.mode == "CTR"):
            tmp = self.BlockCipherEncrypt(self.counter)
            encrypted = self.m_xor(data, tmp)
            self.counter = self.increment(self.counter)
            return encrypted
        """

    def ProcessBlockDecrypt(self, data, isFinal, padding):
        if self.last_block_d is None:
            self.last_block_d = data

        if (self.mode == "ECB"):
            decrypted = self.BlockCipherDecrypt(data)
            if isFinal and padding == "PKCS7":
                decrypted = self.pkcs7_unpad(decrypted)
            return decrypted

        if (self.mode == "CBC"):
            tmp = self.BlockCipherDecrypt(data)
            decrypted = self.m_xor(tmp, self.last_block_d)
            self.last_block_d = data
            if (isFinal):
                return self.pkcs7_unpad(decrypted)
            return decrypted
        
        if (self.mode == "CFB"):
            tmp = self.BlockCipherEncrypt(self.last_block_d)
            decoded = self.m_xor(data, tmp)
            self.last_block_d = data
            return decoded
        
        if (self.mode == "OFB"):
            tmp = self.BlockCipherEncrypt(self.last_block_d)
            self.last_block_d = tmp
            decoded = self.m_xor(data, tmp)
            return decoded
        
        if (self.mode == "CTR"):
            tmp = self.BlockCipherEncrypt(self.last_block_d)
            decoded = self.m_xor(data, tmp)
            self.last_block_d = self.increment(self.last_block_d)
            return decoded
        
        """if (self.mode == "CTR"):
            tmp = self.BlockCipherEncrypt(self.counter)
            decoded = self.m_xor(tmp, data)
            self.counter = self.increment(self.counter)
            return decoded
        """
            
    def Encrypt(self, data, iv=None):
        self.last_block_e = None
        res = b""
        if self.mode in ["CBC", "CFB", "OFB", "CTR"]:
            if iv is None or len(iv) != BLOCK_CHUNK:
                iv = get_random_bytes(BLOCK_CHUNK)
            self.last_block_e = iv

        padding = "PKCS7" if self.mode in ["ECB", "CBC"] else "NON"

        arr_of_blocks = [data[i:i + BLOCK_CHUNK] for i in range(0, len(data), BLOCK_CHUNK)]

        for b in arr_of_blocks[:-1]:
            res += self.ProcessBlockEncrypt(b, False, padding)
        res += self.ProcessBlockEncrypt(arr_of_blocks[-1], True, padding)
        return res

    def Decrypt(self, data, iv=None):
        # self.counter = iv if iv else b"\x00" * BLOCK_CHUNK
        self.last_block_d = None
        res = b""
        if self.mode in ["CBC", "CFB", "OFB", "CTR"]:
            if iv is None or len(iv) != BLOCK_CHUNK:
                iv = data[:BLOCK_CHUNK]
                data = data[BLOCK_CHUNK:]
            self.last_block_d = iv

        padding = "PKCS7" if self.mode in ["ECB", "CBC"] else "NON"

        arr_of_blocks = [data[i:i + BLOCK_CHUNK] for i in range(0, len(data), BLOCK_CHUNK)]
        if not arr_of_blocks:
            return b""
        for b in arr_of_blocks[:-1]:
            res += self.ProcessBlockDecrypt(b, False, padding)
        res += self.ProcessBlockDecrypt(arr_of_blocks[-1], True, padding)

        return res


from Crypto.Util import Counter
from Crypto import Random


def test_aes_modes():
    key = get_random_bytes(16)
    #data = b"yellow submarine yellow submarine"
    data = b"train make sound\nchooo chooooo\nand behind hears\nmoooo moooo"

    iv = get_random_bytes(BLOCK_CHUNK)

    cipher = AESHandler()
    cipher.SetKey(key)

    # ECB
    cipher.SetMode("ECB")
    encrypted_ecb = cipher.Encrypt(data)
    decrypted_ecb = cipher.Decrypt(encrypted_ecb)
    print("Custom AES ECB Encrypted:", binascii.hexlify(encrypted_ecb))
    print("Custom AES ECB Decrypted:", decrypted_ecb.decode('ascii'))

    # lib ECB
    lib_aes= AES.new(key=key, mode=AES.MODE_ECB).encrypt(pad(data, BLOCK_CHUNK))
    assert lib_aes== encrypted_ecb
    assert data == decrypted_ecb
    print("ECB test passed!\n")

    # CBC
    cipher.SetMode("CBC")
    encrypted_cbc = cipher.Encrypt(data, iv)
    decrypted_cbc = cipher.Decrypt(encrypted_cbc, iv)
    print("Custom AES CBC Encrypted:", binascii.hexlify(encrypted_cbc))
    print("Custom AES CBC Decrypted:", decrypted_cbc.decode('ascii'))

    # lib CBC
    lib_aes= AES.new(key=key, mode=AES.MODE_CBC, iv=iv).encrypt(pad(data, BLOCK_CHUNK))
    assert lib_aes== encrypted_cbc
    assert data == decrypted_cbc
    print("CBC test passed!")

    # CFB
    cipher.SetMode("CFB")
    encrypted_cfb = cipher.Encrypt(data, iv)
    decrypted_cfb = cipher.Decrypt(encrypted_cfb, iv)
    print("Custom AES CFB Encrypted:", binascii.hexlify(encrypted_cfb))
    print("Custom AES CFB Decrypted:", decrypted_cfb.decode('ascii'))

    # lib CFB
    lib_aes= AES.new(key=key, mode=AES.MODE_CFB, iv=iv, segment_size=BLOCK_CHUNK * 8).encrypt(data)
    assert lib_aes== encrypted_cfb
    assert data == decrypted_cfb
    print("CFB test passed!")
    
    # OFB
    cipher.SetMode("OFB")
    encrypted_ofb = cipher.Encrypt(data, iv)
    decrypted_ofb = cipher.Decrypt(encrypted_ofb, iv)
    print("Custom AES OFB Encrypted:", binascii.hexlify(encrypted_ofb))
    print("Custom AES OFB Decrypted:", decrypted_ofb.decode('ascii'))

    # lib CFB
    lib_aes= AES.new(key=key, mode=AES.MODE_OFB, iv=iv).encrypt(data)
    assert lib_aes== encrypted_ofb
    assert data == decrypted_ofb
    print("OFB test passed!")

     # CTR
    cipher.SetMode("CTR")
    encrypted_ctr = cipher.Encrypt(data, iv)
    decrypted_ctr = cipher.Decrypt(encrypted_ctr, iv)
    print("Custom AES CTR Encrypted:", binascii.hexlify(encrypted_ctr))
    print("Custom AES CTR Decrypted:", decrypted_ctr.decode('ascii'))

    # lib CTR
    nonce = Random.get_random_bytes(8)
    countf = Counter.new(64, nonce) 
    lib_aes= AES.new(key=key, mode=AES.MODE_CTR, counter=countf).encrypt(data)
    assert data == decrypted_ctr
    print("CTR test passed!\n")


def test_git():
    #test 1
    key = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
    data = bytes.fromhex("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81")
    cipher = AESHandler()
    cipher.SetMode("CBC")
    cipher.SetKey(key)

    res1 = cipher.Decrypt(data)
    print(res1)

    #test 2
    key = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
    data = bytes.fromhex("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253")
    cipher = AESHandler()
    cipher.SetMode("CBC")
    cipher.SetKey(key)

    res2 = cipher.Decrypt(data)
    print(res2)

    #test 3
    key = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")
    data = bytes.fromhex("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329")
    cipher = AESHandler()
    cipher.SetMode("CTR")
    cipher.SetKey(key)

    res3 = cipher.Decrypt(data)
    print(res3)

    #test 4
    key = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")
    data = bytes.fromhex("770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451")
    cipher = AESHandler()
    cipher.SetMode("CTR")
    cipher.SetKey(key)

    res4 = cipher.Decrypt(data)
    print(res4)



if __name__ == '__main__':
    test_aes_modes()
    print("\n" + "-" * 60 + "\n")
    test_git()