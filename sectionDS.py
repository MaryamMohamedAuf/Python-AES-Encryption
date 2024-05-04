
# from crypto.Cipher import AES
# from crypto.Random import get_random_bytes
# from crypto.Util.Padding import pad, unpad

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad 

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(message, AES.block_size))
    return cipher.iv + cipher_text

def decrypt_message(cipher_text, key):
    iv = cipher_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(cipher_text[AES.block_size:]), AES.block_size)
    return decrypted_text

# Generate a random 256-bit (32-byte) key
key = get_random_bytes(32)

# Your message to encrypt
message = b"Hello, world!"

# Encrypt the message
cipher_text = encrypt_message(message, key)

print("Encrypted message:", cipher_text)

# Decrypt the message
plain_text = decrypt_message(cipher_text, key)

print("Decrypted message:", plain_text.decode())


