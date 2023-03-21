#! /usr/bin/python3


from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256, SHA512, SHA3_256
from Cryptodome.Signature import DSS
from Cryptodome.PublicKey import DSA, RSA
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64decode, b64encode
from time import time_ns
from AES_CTR import AES_CTR
from AES_CBC import AES_CBC
from DSA_ import DSA_
from Hashing_ import sha_, per_byte_hash
from RSA_ import RSA_, per_byte_enc, per_byte_dec

print()
print("-----------------------AES CTR encryption/decryption-----------------------")
print(f"AES-CTR 128-bit key with 1KB file :{AES_CTR(16,'package_1',mode=AES.MODE_CTR)}")
print(f"AES-CTR 128-bit key with 10MB file :{AES_CTR(16,'package_2',mode=AES.MODE_CTR)}")
print(f"AES-CTR 256-bit key with 1KB file :{AES_CTR(32,'package_1',mode=AES.MODE_CTR)}")
print(f"AES-CTR 256-bit key with 10MB file :{AES_CTR(32,'package_2',mode=AES.MODE_CTR)}")

print()
print("-----------------------AES CBC encryption/decryption-----------------------")
print(f"AES-CBC 128-bit key with 1KB file :{AES_CBC(16,'package_1',mode=AES.MODE_CBC)}")
print(f"AES-CBC 128-bit key with 10MB file :{AES_CBC(16,'package_2',mode=AES.MODE_CBC)}")
print(f"AES-CBC 256-bit key 1KB file :{AES_CBC(32,'package_1',mode=AES.MODE_CBC)}")
print(f"AES-CBC 256-bit key with 10MB file :{AES_CBC(32,'package_2',mode=AES.MODE_CBC)}")

print()
print("-----------------------HASHING-----------------------")
print(f"\nSHA-256 with 1KB file :{sha_('256','package_1')}")
print(f"\nSHA-256 with 10MB file :{sha_('256','package_2')}")
print(f"\nSHA-512 with 1KB file :{sha_('512','package_1')}")
print(f"\nSHA-512 with 10MB file :{sha_('512','package_2')}")
print(f"\nSHA3-256 with 1KB file :{sha_('3-256','package_1')}")
print(f"\nSHA3-256 with 10MB file :{sha_('3-256','package_2')}")

print()
print("-----------------------RSA encryption/decryption-----------------------")
print(f"2048 bit key with 1KB file : {RSA_(2048,'package_1')}")
print(f"2048 bit key with 1MB file : {RSA_(2048,'file_rsa')}")
print(f"3072 bit key with 1KB file : {RSA_(3072,'package_1')}")
print(f"3072 bit key with 1MB file : {RSA_(3072,'file_rsa')}")


print()
print("-----------------------DSA-----------------------")
print(f"2048 bit key with 1KB file : {DSA_(2048,'package_1')}")
print(f"2048 bit key with 10MB file : {DSA_(2048,'package_2')}")
print(f"3072 bit key with 1KB file : {DSA_(3072,'package_1')}")
print(f"3072 bit key with 10MB file : {DSA_(3072,'package_2')}")

