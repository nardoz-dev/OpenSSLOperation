from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256

def create_signature(message: bytes, private_key: RSA.RsaKey) -> bytes:
    # Hash the message using SHA-256.
    hasher = SHA256.new()
    hasher.update(message)
    hash = hasher.digest()

    # Encrypt the hash using the private key and OAEP padding.
    cipher = PKCS1_OAEP.new(private_key)
    signature = cipher.encrypt(hash)

    # Encrypt the signature using AES-CBC.
    key = b'Sixteen byte key'
    iv = b'Sixteen byte ivv'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    signature_encrypted = cipher.encrypt(signature)

    return signature_encrypted


# Generate a new RSA key pair.
key = RSA.generate(2048)

# Get the private key and public key.
private_key = key.export_key()
public_key = key.publickey().export_key()

# Create the signature for a message.
message = b'This is the message to be signed.'
signature = create_signature(message, private_key)

# The signature can be verified using the public key.
cipher = PKCS1_OAEP.new(public_key)
hash = cipher.decrypt(signature)

# Hash the message using SHA-256.
hasher = SHA256.new()
hasher.update(message)
hash_original = hasher.digest()

# Compare the hashes.
if hash == hash_original:
    print('Signature is valid')
else:
    print('Signature is invalid')


