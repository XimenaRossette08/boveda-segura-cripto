import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

print("Generando llaves...")

# 1. Llave Simétrica (Fernet)
symmetric_key = Fernet.generate_key()
with open(".env", "w") as f:
    f.write(f"SECRET_SYMMETRIC_KEY={symmetric_key.decode()}\n")

# 2. Llaves Asimétricas (RSA)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

public_key = private_key.public_key()
with open("public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("¡Llaves generadas con éxito! Archivos creados: .env, private_key.pem, public_key.pem")