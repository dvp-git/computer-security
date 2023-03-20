from Cryptodome.Cipher import Salsa20
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from base64 import b64decode, b64encode
from Cryptodome.Util.Padding import pad, unpad
from time import time_ns
# key = b'0123456789012345'

# cipher = Salsa20.new(key)
# ciphertext = cipher.encrypt(b'The first part of the message I wish to encrypt')
# ciphertext += cipher.encrypt(b'The second part')

# print(cipher.nonce)
# AES block cipher
#key = get_random_bytes(16)  # 128-bits key

# Encode the key as 64 bit base( pads 2 equal sign).
# Then decode as a UTF-8 string. Results in 22 ascii characters with 2 '=' padding
# print(b64encode(key).decode('utf-8'))   


# DATA
#     MODE_CBC = 2
#     MODE_CCM = 8
#     MODE_CFB = 3
#     MODE_CTR = 6
#     MODE_EAX = 9
#     MODE_ECB = 1
#     MODE_GCM = 11
#     MODE_OCB = 12
#     MODE_OFB = 5
#     MODE_OPENPGP = 7
#     MODE_SIV = 10
#     block_size = 16
#     key_size = (16, 24, 32)

def enc_speed(size, enc_time):
    return size / enc_time

def dec_speed(size, dec_time):
    return size / dec_time

"""AES CBC mode"""
def AES_CBC(file_1, file_2, mode):
    
    with open('package_2','rb') as f_obj:
        plaintext_bytes = f_obj.read()

    # print(plaintext_bytes[:10])

    # Encryption
    start_key_time = time_ns()
    key_AES = get_random_bytes(16)
    end_key_time = time_ns()

    # Instantiate CBC object
    cipher_AES_CBC  = AES.new(key_AES, AES.MODE_CBC, use_aesni=True)

    #Encrypt the data
    start_enc_time = time_ns()
    ciphertext_bytes = cipher_AES_CBC.encrypt(pad(plaintext_bytes, AES.block_size))
    end_enc_time = time_ns()

    iv = b64encode(cipher_AES_CBC.iv).decode('utf-8')
    cipher_text = b64encode(ciphertext_bytes).decode('utf-8')

    # print(iv)
    # print(cipher_text[:20])

    # Decryption:
    try:
        iv = b64decode(iv)
        cipher_text = b64decode(cipher_text)
        decipher_AES_CBC = AES.new(key_AES, AES.MODE_CBC, iv)

        start_dec_time = time_ns()
        plaintext_text_with_pad = decipher_AES_CBC.decrypt(cipher_text)
        end_dec_time = time_ns()

        plaintext_text  = unpad(plaintext_text_with_pad,AES.block_size)
        # print("The message was ",plaintext_text[:10])
    except (ValueError, KeyError):
        print("Incorrent decryption")



    #Key generation time
    key_gen_time = end_key_time - start_key_time

    enc_time = end_enc_time - start_enc_time 

    dec_time = end_dec_time - start_dec_time 

    # if plaintext_text == plaintext_bytes:
    #     print("SUCCESS")

    print(f"\n\nKeyGen Time :{key_gen_time} ,Enc Time: {enc_time}, Dec Time: {dec_time} nanoseconds" )

