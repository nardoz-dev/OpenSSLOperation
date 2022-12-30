import base64
from Crypto.Cipher import Blowfish

# Set the key. This must be kept secret.
key = b'Eight to fifty six byte key'

# The message to be encrypted.
message = b'This is the message to be encrypted.'

# Pad the message to a multiple of 8 bytes so that it can be encrypted.
padding = b' ' * (8 - (len(message) % 8))
message = message + padding

# Create the cipher object and encrypt the message.
cipher = Blowfish.new(key, Blowfish.MODE_ECB)
ciphertext = cipher.encrypt(message)

# Encode the ciphertext as a base64 string for transport.
ciphertext_b64 = base64.b64encode(ciphertext)

# To decrypt the ciphertext, we need the key again.
cipher = Blowfish.new(key, Blowfish.MODE_ECB)

# Decode the base64 ciphertext and decrypt it.
plaintext = cipher.decrypt(base64.b64decode(ciphertext_b64)).rstrip()

print(f'Original message: {message}')
print(f'Encrypted message: {ciphertext_b64}')
print(f'Decrypted message: {plaintext}')
