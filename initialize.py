import random
import string
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Generate EC private key
private_key = ec.generate_private_key(ec.SECP256R1())

# Serialize to PEM (PKCS#8 for private, SubjectPublicKeyInfo for public)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save to files
with open("ec_private.pem", "wb") as f:
    f.write(private_pem)

with open("ec_public.pem", "wb") as f:
    f.write(public_pem)

print("Keys written to ec_private.pem and ec_public.pem")

# Generating testing objects

def generate_random_object(num_attributes=100):
    obj = {}
    for _ in range(num_attributes):
        key = ''.join(random.choices(string.ascii_lowercase, k=5))
        value = ''.join(random.choices(string.ascii_lowercase, k=5))
        obj[key] = value
    return obj

# Generate 1000 JSON objects and save each to a file
for i in range(1000):
    json_object = generate_random_object()
    with open(f'./objects/object_{i:04d}.json', 'w') as f:
        json.dump(json_object, f, indent=4)
