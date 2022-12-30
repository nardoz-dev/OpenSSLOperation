from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

# Generate a new RSA key pair
rsa = RSA.generate(2048)

# Sign a message
message = b'Hello, World!'
message_digest = SHA256.new(message)
signature = PKCS1_v1_5.new(rsa).sign(message_digest)

# Verify the signature
if PKCS1_v1_5.new(rsa).verify(message_digest, signature):
    print('Signature verification successful!')
else:
    print('Signature verification failed!')
