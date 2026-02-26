from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature



# GERAR CHAVES

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()



# MENSAGEM 

mensagem = "Você é fera!"



# CONFIDENCIALIDADE

# criptografar com chave pública
cipher = public_key.encrypt(
    mensagem.encode(),
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# descriptografar com chave privada
original = private_key.decrypt(
    cipher,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)



# AUTENTICIDADE

# assinar com chave privada
assinatura = private_key.sign(
    mensagem.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# verificar com chave pública
try:
    public_key.verify(
        assinatura,
        mensagem.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    verificado = True
except InvalidSignature:
    verificado = False



# RESULTADOS

print("=== CONFIDENCIALIDADE ===")
print("Mensagem original:", mensagem)
print("Mensagem cifrada :", cipher.hex())
print("Mensagem decifrada:", original.decode())

print("\n=== AUTENTICIDADE ===")
print("Assinatura válida?", verificado)