
"""PKCS #1 OAEP"""
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP
from time import time_ns

# Generate the RSA key
start_key_time = time_ns()
key = RSA.generate(2048)
end_key_time = time_ns()


# Save pvt key file
secret_code = "S@cret123_4"
private_key = key.export_key(passphrase=secret_code)

file_out = open("privateRSA.pem","wb")
file_out.write(private_key)
file_out.close()

# Save public key file
public_key = key.publickey().export_key()
file_out = open("publicRSA.pem","wb")
file_out.write(public_key)
file_out.close()

# Encrypt file
file_out = open("encrypted_data.bin","wb")

# Use public key for encryption
public_enc_key = open("publicRSA.pem").read()

# Use private key for decryption
recipient_key = RSA.import_key(public_enc_key)


# Instantiate PKCS object
cipher_RSA  = PKCS1_OAEP.new(recipient_key, use_aesni=True)


#Encrypt the data
start_enc_time = time_ns()
ciphertext_bytes = cipher_AES_CBC.encrypt(pad(plaintext_bytes, AES.block_size))
end_enc_time = time_ns()

iv = b64encode(cipher_AES_CBC.iv).decode('utf-8')
cipher_text = b64encode(ciphertext_bytes).decode('utf-8')



# Decrypt with private key
