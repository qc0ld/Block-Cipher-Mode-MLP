import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from BlockCipher import BlockCipher, EncryptionMode


def main():
    ####################### TASK 2.5 #######################
    print("\nTASK 2.5")

    text = b"Completely-random-text-aaa-dddd-bbbb-ppppp"
    key = b"sixteen-byte-key"
    iv = b"sixteen-bytes-iv"

    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(text, AES.block_size))

    block_cipher = BlockCipher()
    block_cipher.set_key(key)
    block_cipher.set_mode(EncryptionMode.CBC)
    decrypted_data = block_cipher.decrypt(encrypted_data, iv)

    print("Encrypt with Crypto -> Decrypt with BlockCipher")
    print("Original Text:", text)
    print("Encrypted Data:", encrypted_data)
    print("Decrypted Data:", decrypted_data)
    #------------------------------------------------------#
    encrypted_data = block_cipher.encrypt(text, iv)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    print("Encrypt with BlockCipher -> Decrypt with Crypto")
    print("Original Text:", text)
    print("Encrypted Data:", encrypted_data)
    print("Decrypted Data:", decrypted_data)
    ######################## TASK 3 ########################
    print("\nTASK 3")

    text = bytes.fromhex("28a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81")
    key = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
    iv = bytes.fromhex("4ca00ff4c898d61e1edbf1800618fb28")

    block_cipher.set_key(key)
    decrypted_data = block_cipher.decrypt(text, iv)

    print("Ciphertext 1: " + str(decrypted_data))
    #-------------------------------------------------------#
    text = bytes.fromhex("b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253")
    key = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
    iv = bytes.fromhex("5b68629feb8606f9a6667670b75b38a5")

    block_cipher.set_key(key)
    decrypted_data = block_cipher.decrypt(text, iv)

    print("Ciphertext 2: " + str(decrypted_data))
    #-------------------------------------------------------#
    text = bytes.fromhex("0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329")
    key = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")
    iv = bytes.fromhex("69dda8455c7dd4254bf353b773304eec")

    block_cipher.set_key(key)
    block_cipher.set_mode(EncryptionMode.CTR)
    decrypted_data = block_cipher.decrypt(text, iv)

    print("Ciphertext 3: " + str(decrypted_data))
    #-------------------------------------------------------#
    text = bytes.fromhex(
        "e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451")
    key = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")
    iv = bytes.fromhex("770b80259ec33beb2561358a9f2dc617")

    block_cipher.set_key(key)
    block_cipher.set_mode(EncryptionMode.CTR)
    decrypted_data = block_cipher.decrypt(text, iv)

    print("Ciphertext 4: " + str(decrypted_data))
    ######################## TASK 4 ########################
    print("\nTASK 4")

    text = b"this-text-is-two-and-a-half-blocks-longg"
    key = b"sixteen-byte-key"
    block_cipher.set_key(key)
    block_cipher.set_mode(EncryptionMode.ECB)
    encrypted_data = block_cipher.encrypt(text)
    decrypted_data = block_cipher.decrypt(encrypted_data)

    print("Original Text:" + str(text))
    print("Encrypted with ECB Text:" + str(encrypted_data))
    print("Decrypted with ECB Text: " + str(decrypted_data))
    #-------------------------------------------------------#
    block_cipher.set_key(key)
    block_cipher.set_mode(EncryptionMode.CBC)
    encrypted_data = block_cipher.encrypt(text, iv)
    decrypted_data = block_cipher.decrypt(encrypted_data, iv)

    print("\nOriginal Text:" + str(text))
    print("Encrypted with CBC Text:" + str(encrypted_data))
    print("Decrypted with CBC Text: " + str(decrypted_data))
    #-------------------------------------------------------#
    block_cipher.set_key(key)
    block_cipher.set_mode(EncryptionMode.CFB)
    encrypted_data = block_cipher.encrypt(text, iv)
    decrypted_data = block_cipher.decrypt(encrypted_data, iv)

    print("\nOriginal Text:" + str(text))
    print("Encrypted with CBF Text:" + str(encrypted_data))
    print("Decrypted with CBF Text: " + str(decrypted_data))
    #-------------------------------------------------------#
    block_cipher.set_key(key)
    block_cipher.set_mode(EncryptionMode.OFB)
    encrypted_data = block_cipher.encrypt(text, iv)
    decrypted_data = block_cipher.decrypt(encrypted_data, iv)

    print("\nOriginal Text:" + str(text))
    print("Encrypted with OFB Text:" + str(encrypted_data))
    print("Decrypted with OFB Text: " + str(decrypted_data))
    #-------------------------------------------------------#
    block_cipher.set_key(key)
    block_cipher.set_mode(EncryptionMode.CTR)
    encrypted_data = block_cipher.encrypt(text, iv)
    decrypted_data = block_cipher.decrypt(encrypted_data, iv)

    print("\nOriginal Text:" + str(text))
    print("Encrypted with CTR Text:" + str(encrypted_data))
    print("Decrypted with CTR Text: " + str(decrypted_data))
    #-------------------------------------------------------#


if __name__ == '__main__':
    main()