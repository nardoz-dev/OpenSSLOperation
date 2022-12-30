import base64
from Crypto.Cipher import AES

# Set the key and initialization vector (IV). These must be kept secret.
key = b'Sixteen byte key'
iv = b'Sixteen byte ivv'

# The message to be encrypted.
message = b'This is the message to be encrypted.'

# Pad the message to a multiple of 16 bytes so that it can be encrypted.
padding = b' ' * (16 - (len(message) % 16))
message = message + padding

# Create the cipher object and encrypt the message.
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(message)

# Encode the ciphertext as a base64 string for transport.
ciphertext_b64 = base64.b64encode(ciphertext)

# To decrypt the ciphertext, we need the key and IV again.
cipher = AES.new(key, AES.MODE_CBC, iv)

# Decode the base64 ciphertext and decrypt it.
plaintext = cipher.decrypt(base64.b64decode(ciphertext_b64)).rstrip()

print(f'Original message: {message}')
print(f'Encrypted message: {ciphertext_b64}')
print(f'Decrypted message: {plaintext}')
