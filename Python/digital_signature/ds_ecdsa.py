from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import dsa
import hashlib
from cryptography.hazmat.backends import default_backend

# Generate a new ECDSA key pair
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Sign a message
message = b'Hello, World!'
# Compute the hash of the message using SHA256
message_digest = hashlib.sha256(message).digest()
signature = private_key.sign(message_digest, ec.ECDSA(SHA256()))

# Verify the signature
public_key.verify(signature, message_digest, ec.ECDSA(SHA256()))
print('Signature verification successful!')
