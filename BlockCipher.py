from enum import Enum
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets


class EncryptionMode(Enum):
    ECB = "ECB"
    CBC = "CBC"
    CFB = "CFB"
    OFB = "OFB"
    CTR = "CTR"


def xor(str1, str2):
    return bytes(a ^ b for a, b in zip(str1, str2))


def increment_counter(counter):
    int_counter = int.from_bytes(counter)
    incremented_counter = int_counter + 1
    return incremented_counter.to_bytes(len(counter))


def get_iv(block_size):
    return secrets.token_bytes(block_size)


class BlockCipher:
    def __init__(self):
        self.block_size = 16
        self.key = None
        self.mode = None
        self.iv = None

    def set_key(self, key):
        if len(key) == self.block_size:
            self.key = key
        else:
            raise ValueError("Invalid key length")

    def set_mode(self, mode):
        if mode in EncryptionMode:
            self.mode = mode
        else:
            raise ValueError("Invalid mode")

    def block_cipher_encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(data)

    def block_cipher_decrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.decrypt(data)

    def process_block_encrypt(self, data, is_final_block, padding):
        if self.mode == EncryptionMode.ECB:
            if is_final_block:
                data = pad(data, self.block_size, padding)
            return self.block_cipher_encrypt(data)

        elif self.mode == EncryptionMode.CBC:
            if is_final_block:
                data = pad(data, self.block_size, padding)
            data = xor(data, self.iv)
            encrypted_data = self.block_cipher_encrypt(data)
            self.iv = encrypted_data
            return encrypted_data

        elif self.mode == EncryptionMode.CFB:
            self.iv = xor(self.block_cipher_encrypt(self.iv), data)
            return self.iv

        elif self.mode == EncryptionMode.OFB:
            self.iv = self.block_cipher_encrypt(self.iv)
            return xor(self.iv, data)

        elif self.mode == EncryptionMode.CTR:
            counter = self.iv
            encrypted_counter = self.block_cipher_encrypt(counter)
            self.iv = increment_counter(counter)
            return xor(encrypted_counter, data)

    def process_block_decrypt(self, data, is_final_block, padding):
        if self.mode == EncryptionMode.ECB:
            decrypted_data = self.block_cipher_decrypt(data)
            if is_final_block:
                decrypted_data = unpad(decrypted_data, self.block_size, padding)
            return decrypted_data

        elif self.mode == EncryptionMode.CBC:
            decrypted_data = xor(self.block_cipher_decrypt(data), self.iv)
            self.iv = data
            if is_final_block:
                decrypted_data = unpad(decrypted_data, self.block_size, padding)
            return decrypted_data

        elif self.mode == EncryptionMode.CFB:
            cipher = self.block_cipher_encrypt(self.iv)
            self.iv = data
            return xor(cipher, data)

        elif self.mode == EncryptionMode.OFB:
            self.iv = self.block_cipher_encrypt(self.iv)
            return xor(self.iv, data)

        elif self.mode == EncryptionMode.CTR:
            counter = self.iv
            encrypted_counter = self.block_cipher_encrypt(counter)
            self.iv = increment_counter(counter)
            return xor(encrypted_counter, data)

    def encrypt(self, data, iv=None):
        if iv:
            self.iv = iv
        else:
            self.iv = get_iv(self.block_size)

        if self.mode == EncryptionMode.ECB or self.mode == EncryptionMode.CBC:
            padding = "pkcs7"
        else:
            padding = "NON"

        cipher_text = b""
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            is_final_block = i + self.block_size >= len(data)
            cipher_text += self.process_block_encrypt(block, is_final_block, padding)

        return cipher_text

    def decrypt(self, data, iv=None):
        if iv:
            self.iv = iv
        else:
            self.iv = get_iv(self.block_size)

        if self.mode == EncryptionMode.ECB or self.mode == EncryptionMode.CBC:
            padding = "pkcs7"
        else:
            padding = "NON"

        plain_text = b""
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            is_final_block = i + self.block_size >= len(data)
            plain_text += self.process_block_decrypt(block, is_final_block, padding)

        return plain_text
