from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Cryptodome.Random import get_random_bytes
import time
"""
the first parameter is always the cryptographic key (a byte string)

the second parameter is always the constant that selects the desired mode of operatio
"""

def encrypt_speed(size, time_for_encryption):
    # enc_size_per_second = size / (time_for_encryption)
    # enc_speed_per_byte =  1 / (enc_size_per_second)

    return time_for_encryption / size


def decrypt_speed(size, time_for_decryption):
    # dec_size_per_second = size / (time_for_decryption)
    # dec_speed_per_byte =  1 / (dec_size_per_second)
    return time_for_decryption / size

def per_byte_hash(size, hash_time):
    return hash_time / size

def per_bye_dsa_sign(size, signing_time):
    return signing_time / size


def per_byte_dsa_verify(size, verification_time):
    return verification_time / size


# # ------ ------- ------- ------- --------CBC mode:---------- ------- ------- ------- -------
# # Generating 128-bit key
# # def encrypt_decrypt(file_1, file_2):
# keygen_s = time.time_ns()
# key_cbc = get_random_bytes(16)  
# keygen_e = time.time_ns()

# # Keygeneration time
# keygen_time = keygen_e - keygen_s


# print(f"\n\nTime for generating key : {keygen_time} microseconds")


# #Initialization vector initialied randomly
# cipher = AES.new(key_cbc, AES.MODE_CBC,use_aesni=True)

# # Initialization vector encoded and stored as string
# iv  = b64encode(cipher.iv).decode('utf-8')

# with open('package_2','rb') as fileObj:
#     _1_kb_file = fileObj.read()
#     s_enc = time.time()
#     _1_kb_encrypted = cipher.encrypt(pad(_1_kb_file, AES.block_size))
#     e_enc = time.time()

# #Encryption time
# encryption_time = (e_enc - s_enc) * 1000000

# print(f"\n\n Time for encryption of 1 KB file : {encryption_time} microseconds")
# print(f"\n\n Time for encryption of 10 MB file : {encryption_time} microseconds")


# # print(f"\n\n{b64encode(_1_kb_encrypted).decode('utf-8')}")


# with open('encrypted_1_KB','wb') as enc:
#     enc.write(_1_kb_encrypted)


# decipher = AES.new(key_cbc, AES.MODE_CBC, iv=b64decode(iv),use_aesni=True)

# with open('encrypted_1_KB','rb') as dec:
#     decrypted_1_KB = dec.read()
#     s_dec = time.time()
#     decrypted_ = unpad(decipher.decrypt(decrypted_1_KB),AES.block_size)
#     e_dec = time.time()


# decryption_time = (e_dec - s_dec ) * 1000000


# print(f"\n\n Time for decryption of 1 KB file : {decryption_time} microseconds")

# print(f"\n\n Time for decryption of 10MB file : {decryption_time} microseconds")
# #  print(f"\n\n{decrypted_.decode('utf-8')}")


# if _1_kb_file == decrypted_:
#     print("SUCCESS")

# print(f"{encrypt_speed(10485760,encryption_time)} microseconds")
# print(f"{decrypt_speed(10485760,decryption_time)} microseconds")




# # --- ------- ------- ------- -----------CTR mode:---------- ------- ------- ------- ------- -------
# # Generating 128-bit key
# keygen_s = time.time_ns()
# key_ctr = get_random_bytes(16)  
# keygen_e = time.time_ns()

# # Keygeneration time
# keygen_time = keygen_e - keygen_s


# print(f"\n\nTime for generating key : {keygen_time} nanosecond")


# #Initialization vector initialied randomly
# cipher = AES.new(key_ctr, AES.MODE_CTR,use_aesni=True)

# # Initialization vector encoded and stored as string
# nonce  = b64encode(cipher.nonce).decode('utf-8')

# with open('package_1','rb') as fileObj:
#     plaintext_ctr = fileObj.read()
#     s_enc = time.time_ns()
#     ciphertext_ctr = cipher.encrypt(plaintext_ctr)
#     e_enc = time.time_ns()

# #Encryption time
# encryption_time = (e_enc - s_enc) 

# print(f"\n\n Time for encryption of 1 KB file : {encryption_time} nanosecond")
# print(f"\n\n Time for encryption of 10 MB file : {encryption_time} nanosecond")

# print(f"\n\n{b64encode(ciphertext_ctr).decode('utf-8')}")

# with open('encrypted_1KB_ctr_16','wb') as enc:
#     enc.write(ciphertext_ctr)


# decipher = AES.new(key_ctr, AES.MODE_CTR,nonce=b64decode(nonce),use_aesni=True)

# with open('encrypted_1KB_ctr_16','rb') as dec:
#     decrypted_ctr_read = dec.read()
#     s_dec = time.time_ns()
#     decrypted_ctr = decipher.decrypt(decrypted_ctr_read)
#     e_dec = time.time_ns()

# decryption_time = (e_dec - s_dec )


# print(f"\n\n Time for decryption of 1 KB file : {decryption_time}  nanosecond")
# print(f"\n\n Time for decryption of 10MB file : {decryption_time} nanosecond")
# print(f"\n\n{decrypted_.decode('utf-8')}")


# if plaintext_ctr == decrypted_:
#     print("SUCCESS")

# print(f"{encrypt_speed(1000,encryption_time) } nanosecond")
# print(f"{decrypt_speed(1000,decryption_time) } nanosecond")





# -------------------------------------------------------c ) CTR mode:-------------------------------------------------vv-
# Generating 256-bit key
# keygen_s = time.time_ns()
# key_ctr_2 = get_random_bytes(32)  
# keygen_e = time.time_ns()

# # Keygeneration time
# keygen_time = keygen_e - keygen_s


# print(f"\n\nTime for generating key : {keygen_time} nanosecond")


# #Initialization vector initialied randomly
# cipher = AES.new(key_ctr_2, AES.MODE_CTR,use_aesni=True)

# # Initialization vector encoded and stored as string
# nonce  = b64encode(cipher.nonce).decode('utf-8')

# with open('package_1','rb') as fileObj:
#     plaintext_ctr_2 = fileObj.read()
#     s_enc = time.time_ns()
#     ciphertext_ctr_2 = cipher.encrypt(plaintext_ctr_2)
#     e_enc = time.time_ns()

# #Encryption time
# encryption_time = (e_enc - s_enc) 

# print(f"\n\n Time for encryption of 1 KB file : {encryption_time} nanosecond")
# print(f"\n\n Time for encryption of 10 MB file : {encryption_time} nanosecond")


# print(f"\n\n{b64encode(ciphertext_ctr_2).decode('utf-8')}")


# with open('encrypted_ctr_2','wb') as enc:
#     enc.write(ciphertext_ctr_2)


# decipher = AES.new(key_ctr_2, AES.MODE_CTR,nonce=b64decode(nonce),use_aesni=True)

# with open('encrypted_ctr_2','rb') as dec:
#     decrypted_ctr2_read = dec.read()
#     s_dec = time.time_ns()
#     decrypted_ctr_2 = decipher.decrypt(decrypted_ctr2_read)
#     e_dec = time.time_ns()


# decryption_time = (e_dec - s_dec )


# print(f"\n\n Time for decryption of 1 KB file : {decryption_time}  nanosecond")

# print(f"\n\n Time for decryption of 10MB file : {decryption_time} nanosecond")
# print(f"\n\n{decrypted_ctr_2.decode('utf-8')}")


# if plaintext_ctr_2 == decrypted_ctr_2:
#     print("SUCCESS")

# print(f"{encrypt_speed(1000,encryption_time) } nanosecond")
# print(f"{decrypt_speed(1000,decryption_time) } nanosecond")



# # # # # # # # # # # # # # # #  2048 bit RSA # # # # # # # # # # # # # # # # # # 
# from Cryptodome.PublicKey import RSA
# from Cryptodome.Cipher import PKCS1_OAEP


# # Key generation:
# s_rsa_gen = time.time_ns()
# key_rsa = RSA.generate(2048)
# e_rsa_gen = time.time_ns()


# key_pvt_rsa = key_rsa.export_key()
# file_pvt_obj = open('myRsaPvtKey.pem','wb')
# file_pvt_obj.write(key_pvt_rsa)
# file_pvt_obj.close()

# key_public_rsa = key_rsa.export_key()
# file_pub_obj = open('myRsaPublicKey.pem','wb')
# file_pub_obj.write(key_public_rsa)
# file_pub_obj.close()



# # Encrypting
# key_s = RSA.import_key(open('myRsaPublicKey.pem').read())
# cipher_rsa_1 = PKCS1_OAEP.new(key_s)


# with open('package_1','rb') as fileObj:
#     rsa_file_1 = fileObj.read()
#     s_rsa_enc = time.time_ns()
#     ciphertext_1 = cipher_rsa_1.encrypt(rsa_file_1)
#     e_rsa_enc = time.time_ns()
    

    
# print(f"{b64encode(ciphertext_1).decode('utf-8')}")
# print()
# #Encryption time
# encryption_time_rsa = (e_rsa_enc - s_rsa_enc)

# print(f"\n\n Time for encryption of 1 KB file : {encryption_time_rsa} nanoseconds")
# print(f"\n\n Time for encryption of 10 MB file : {encryption_time_rsa} nanoseconds")


# #Decrypting
# key_r = RSA.import_key(open('myRsaPvtKey.pem').read())
# decipher_rsa_1 = PKCS1_OAEP.new(key_r)
# s_rsa_dec = time.time_ns()
# message = decipher_rsa_1.decrypt(ciphertext_1)
# e_rsa_dec = time.time_ns()

# decryption_time_rsa = (e_rsa_dec - s_rsa_dec )

# print(f"\n\n Time for encryption of 1 KB file : {decryption_time_rsa} nanoseconds")
# print(f"\n\n Time for encryption of 10 MB file : {decryption_time_rsa} nanoseconds")

# print(message)



# # # # # # # # # # # # # # 3072-bit RSA # # # # # # # # # # # # # # 
# # Key generation:
# s_rsa_2_gen = time.time_ns()
# key_rsa_2 = RSA.generate(3072)
# e_rsa_2_gen = time.time_ns()


# key_pvt_rsa_2 = key_rsa_2.export_key()
# file_pvt_obj_2= open('myRsaPvtKey2.pem','wb')
# file_pvt_obj_2.write(key_pvt_rsa_2)
# file_pvt_obj_2.close()

# key_public_rsa_2 = key_rsa_2.export_key()
# file_pub_obj_2 = open('myRsaPublicKey2.pem','wb')
# file_pub_obj_2.write(key_public_rsa_2)
# file_pub_obj_2.close()



# # Encrypting
# key_s_2 = RSA.import_key(open('myRsaPublicKey2.pem').read())
# cipher_rsa_2 = PKCS1_OAEP.new(key_s_2)


# with open('package_1','rb') as fileObj:
#     rsa_file_2 = fileObj.read()
#     s_rsa_enc_2 = time.time_ns()
#     ciphertext_2 = cipher_rsa_2.encrypt(rsa_file_2)
#     e_rsa_enc_2 = time.time_ns()
    

    
# print(f"{b64encode(ciphertext_2).decode('utf-8')}")
# print()
# #Encryption time
# encryption_time_rsa_2 = (e_rsa_enc_2 - s_rsa_enc_2)

# print(f"\n\n Time for encryption of 1 KB file : {encryption_time_rsa_2} nanoseconds")
# print(f"\n\n Time for encryption of 10 MB file : {encryption_time_rsa_2} nanoseconds")


# #Decrypting
# key_r_2 = RSA.import_key(open('myRsaPvtKey2.pem').read())
# decipher_rsa_2 = PKCS1_OAEP.new(key_r_2)
# s_rsa_dec_2 = time.time_ns()
# message = decipher_rsa_1.decrypt(ciphertext_2)
# e_rsa_dec_2 = time.time_ns()

# decryption_time_rsa_2 = (e_rsa_dec_2 - s_rsa_dec_2 )

# print(f"\n\n Time for encryption of 1 KB file : {decryption_time_rsa_2} nanoseconds")
# print(f"\n\n Time for encryption of 10 MB file : {decryption_time_rsa_2} nanoseconds")

# print(message)


# # # # # # # # # # # # # # # # # # # # # #  Hash files # # # # # # # # # # # # # # # # # # # # # # # # 
# Sha-256

from Cryptodome.Hash import SHA256 , SHA512 , SHA3_256

# file_h256 = open('package_1','rb') 
# content_256 = file_h256.read()
# file_h256.close()



# h_256 = SHA256.new()
# h_256_start = time.time_ns()
# h_256.update(content_256)
# h_256_end = time.time_ns()

# hashing_256_tme = h_256_end - h_256_start
# print(f"{b64encode(content_256).decode('utf-8')}")
# print()
# print(f"{h_256.hexdigest()}")

# print(f"\n\n Time for hashing is of 1 KB file : {hashing_256_tme} nanoseconds")


# print(f"\n\n Time for hashing is of 10 MB file : {hashing_256_tme} nanoseconds")


# print(f"Per Byte Hash time {per_byte_hash(1000,hashing_256_tme)} nanoseconds")
# print(f"Per Byte Hash time {per_byte_hash(1000000,hashing_256_tme)} nanoseconds")




# Sha-512
# file_h512 = open('package_1','rb') 
# content_512 = file_h512.read()
# file_h512.close()



# h_512 = SHA512.new()
# h_512_start = time.time_ns()
# h_512.update(content_512)
# h_512_end = time.time_ns()

# hashing_512_tme = h_512_end - h_512_start
# print(f"{b64encode(content_512).decode('utf-8')}")

# print(f"{h_512.hexdigest()}")


# print(f"\n\n Time for hashing is of 1 KB file : {hashing_512_tme} nanoseconds")


# print(f"\n\n Time for hashing is of 10 MB file : {hashing_512_tme} nanoseconds")


# print(f"Per Byte Hash time {per_byte_hash(1000,hashing_512_tme)} nanoseconds")
# print(f"Per Byte Hash time {per_byte_hash(1000000,hashing_512_tme)} nanoseconds")





# Sha3-256
# file_h3256 = open('package_1','rb') 
# content_3256 = file_h3256.read()
# file_h3256.close()



# h_3256 = SHA256.new()
# h_3256_start = time.time_ns()
# h_3256.update(content_3256)
# h_3256_end = time.time_ns()

# hashing_3256_tme = h_3256_end - h_3256_start
# print(f"{b64encode(content_3256).decode('utf-8')}")
# print()
# print(f"{h_3256.hexdigest()}")
# print(f"\n\n Time for hashing is of 1 KB file : {hashing_3256_tme} nanoseconds")


# print(f"\n\n Time for hashing is of 10 MB file : {hashing_3256_tme} nanoseconds")


# print(f"Per Byte Hash time {per_byte_hash(1000,hashing_3256_tme)} nanoseconds")
# print(f"Per Byte Hash time {per_byte_hash(1000000,hashing_3256_tme)} nanoseconds")

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

# DSA key :
# 2048 bit DSA key , sign the files, verify signatures

# from Cryptodome.PublicKey import DSA
# from Cryptodome.Signature import DSS
# from Cryptodome.Hash import SHA256

# # Create a new key

# dsa_key_start = time.time_ns()
# key_dsa = DSA.generate(2048)
# dsa_key_end = time.time_ns()

# key_gen_dsa = dsa_key_end - dsa_key_start
# print(f" Time it takes for key {key_gen_dsa} nanoseconds")

# f = open("public_dsa_key.pem","wb")
# f.write(key_dsa.publickey().export_key())
# f.close()


# # Read the file contents
# file1_dsa_1 = open('package_1','rb') 
# file1_dsa_contents = file1_dsa_1.read()
# file1_dsa_1.close()

# file2_dsa_1 = open('package_2','rb') 
# file2_dsa_contents = file2_dsa_1.read()
# file2_dsa_1.close()


# # Sign the files
# hash_obj_1 = SHA256.new(file1_dsa_contents)
# signer_1 = DSS.new(key_dsa,'fips-186-3')
# dsa_sign_start_1 = time.time_ns()
# signature_1 = signer_1.sign(hash_obj_1)
# dsa_sign_end_1 = time.time_ns()

# dsa_sign_1 = dsa_sign_end_1 - dsa_sign_start_1
# print(f" Time to compute signature for file_1 {dsa_sign_1} nanoseconds")



# hash_obj_2 = SHA256.new(file2_dsa_contents)
# signer_2 = DSS.new(key_dsa,'fips-186-3')
# dsa_sign_start_2 = time.time_ns()
# signature_2 = signer_2.sign(hash_obj_2)
# dsa_sign_end_2 = time.time_ns()

# dsa_sign_2 = dsa_sign_end_2 - dsa_sign_start_2
# print(f" Time to compute signature for file_2 {dsa_sign_2} nanoseconds")


# # Load the key
# f = open("public_dsa_key.pem","rb")
# hash_obj_1 = SHA256.new(file1_dsa_contents)
# hash_obj_2 = SHA256.new(file2_dsa_contents)


# pub_key = DSA.import_key(f.read())
# verifier= DSS.new(pub_key,'fips-186-3')


# # Verify the authenticity
# try :
#     dsa_verify_start_1 = time.time_ns()
#     verifier.verify(hash_obj_1, signature_1)
#     dsa_verify_end_1 = time.time_ns()
#     print("The message is authentic")
# except ValueError:
#     print("Message is not authentic")


# # Verify the authenticity
# try :
#     dsa_verify_start_2 = time.time_ns()
#     verifier.verify(hash_obj_2, signature_2)
#     dsa_verify_end_2 = time.time_ns()
#     print("The message is authentic")
# except ValueError:
#     print("Message is not authentic")


# dsa_f1_ver = dsa_verify_end_2 - dsa_verify_start_2
# dsa_f2_ver = dsa_verify_end_1 - dsa_verify_start_1

# print(f" Time it takes for file_1 signature verification {dsa_f1_ver} nanoseconds")
# print(f" Time it takes for file_2 signature verification {dsa_f2_ver} nanoseconds")


# print(f"Per-bye sign time for file_1 {per_bye_dsa_sign(1000,dsa_sign_1)}")
# print(f"Per-bye sign time for file_2 {per_bye_dsa_sign(1000000,dsa_sign_2,)}")
       
# print(f"Per-bye sign verification time for file_1 {per_byte_dsa_verify(1000,dsa_sign_1)}")
# print(f"Per-bye sign verification time for file_2 {per_byte_dsa_verify(1000000,dsa_sign_1)}")





#####################

# SA key :
# 3072 bit DSA key , sign the files, verify signatures

from Cryptodome.PublicKey import DSA
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA256

# Create a new key

dsa_key_start = time.time_ns()
key_dsa = DSA.generate(3072)
dsa_key_end = time.time_ns()

key_gen_dsa = dsa_key_end - dsa_key_start
print(f" Time it takes for key {key_gen_dsa} nanoseconds")

f = open("public_dsa_key.pem","wb")
f.write(key_dsa.publickey().export_key())
f.close()


# Read the file contents
file1_dsa_1 = open('package_1','rb') 
file1_dsa_contents = file1_dsa_1.read()
file1_dsa_1.close()

file2_dsa_1 = open('package_2','rb') 
file2_dsa_contents = file2_dsa_1.read()
file2_dsa_1.close()


# Sign the files
hash_obj_1 = SHA256.new(file1_dsa_contents)
signer_1 = DSS.new(key_dsa,'fips-186-3')
dsa_sign_start_1 = time.time_ns()
signature_1 = signer_1.sign(hash_obj_1)
dsa_sign_end_1 = time.time_ns()

dsa_sign_1 = dsa_sign_end_1 - dsa_sign_start_1
print(f" Time to compute signature for file_1 {dsa_sign_1} nanoseconds")



hash_obj_2 = SHA256.new(file2_dsa_contents)
signer_2 = DSS.new(key_dsa,'fips-186-3')
dsa_sign_start_2 = time.time_ns()
signature_2 = signer_2.sign(hash_obj_2)
dsa_sign_end_2 = time.time_ns()

dsa_sign_2 = dsa_sign_end_2 - dsa_sign_start_2
print(f" Time to compute signature for file_2 {dsa_sign_2} nanoseconds")


# Load the key
f = open("public_dsa_key.pem","rb")
hash_obj_1 = SHA256.new(file1_dsa_contents)
hash_obj_2 = SHA256.new(file2_dsa_contents)


pub_key = DSA.import_key(f.read())
verifier= DSS.new(pub_key,'fips-186-3')


# Verify the authenticity
try :
    dsa_verify_start_1 = time.time_ns()
    verifier.verify(hash_obj_1, signature_1)
    dsa_verify_end_1 = time.time_ns()
    print("The message is authentic")
except ValueError:
    print("Message is not authentic")


# Verify the authenticity
try :
    dsa_verify_start_2 = time.time_ns()
    verifier.verify(hash_obj_2, signature_2)
    dsa_verify_end_2 = time.time_ns()
    print("The message is authentic")
except ValueError:
    print("Message is not authentic")


dsa_f1_ver = dsa_verify_end_2 - dsa_verify_start_2
dsa_f2_ver = dsa_verify_end_1 - dsa_verify_start_1

print(f" Time it takes for file_1 signature verification {dsa_f1_ver} nanoseconds")
print(f" Time it takes for file_2 signature verification {dsa_f2_ver} nanoseconds")


print(f"Per-bye sign time for file_1 {per_bye_dsa_sign(1000,dsa_sign_1)}")
print(f"Per-bye sign time for file_2 {per_bye_dsa_sign(1000000,dsa_sign_2,)}")
       
print(f"Per-bye sign verification time for file_1 {per_byte_dsa_verify(1000,dsa_sign_1)}")
print(f"Per-bye sign verification time for file_2 {per_byte_dsa_verify(1000000,dsa_sign_1)}")












##############################################################################################################################################################



# # Function to encrypt and decrypt:
# def encrypt_decrypt(file_1, file_2, key_size, mode):

#     # -------CBC mode:----------
#     # Generating 128-bit key
#     # def encrypt_decrypt(file_1, file_2):
#     keygen_s = time.time_ns()
#     key = get_random_bytes(key_size)  
#     keygen_e = time.time_ns()

#     # Keygeneration time
#     keygen_time = keygen_e - keygen_s


#     # print(f"\n\nTime for generating key : {keygen_time} nanoseconds")

#     if mode == "CBC":
#         #Initialization vector initialied randomly
#         cipher = AES.new(key, AES.MODE_CBC,use_aesni=True)

#         # Initialization vector encoded and stored as string
#         iv  = b64encode(cipher.iv).decode('utf-8')

#     elif mode == "CTR":
#         cipher = AES.new(key, AES.MODE_CTR,use_aesni=True)

#         # Counter nonce value stored
#         nonce = b64encode(cipher.nonce).decode('utf-8')
    

    

#     with open('package_1','rb') as fileObj:
#         _1_kb_file = fileObj.read()
#         s_enc = time.time_ns()
#         _1_kb_encrypted = cipher.encrypt(pad(_1_kb_file, AES.block_size))
#         e_enc = time.time_ns()

#     #Encryption time
#     encryption_time = e_enc - s_enc

#     print(f"\n\n Time for encryption of 1 KB file : {encryption_time} nanoseconds")


#     print(f"\n\n{b64encode(_1_kb_encrypted).decode('utf-8')}")


#     with open('encrypted_1_KB','wb') as enc:
#         enc.write(_1_kb_encrypted)


#     decipher = AES.new(key, AES.MODE_CBC, iv=b64decode(iv),use_aesni=True)

#     with open('encrypted_1_KB','rb') as dec:
#         decrypted_1_KB = dec.read()
#         s_dec = time.time_ns()
#         decrypted_ = unpad(decipher.decrypt(decrypted_1_KB),AES.block_size)
#         e_dec = time.time_ns()


#     decryption_time = e_dec - s_dec


#     print(f"\n\n Time for decryption of 1 KB file : {decryption_time} nanoseconds")

#     print(f"\n\n{decrypted_.decode('utf-8')}")


#     if _1_kb_file == decrypted_:
#         print("SUCCESS")
