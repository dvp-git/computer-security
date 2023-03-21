
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from base64 import b64decode, b64encode
from Cryptodome.Util.Padding import pad, unpad
from time import time_ns


def per_byte_enc(file_size, enc_time):
    return enc_time / file_size

def per_byte_dec(file_size, dec_time):
    return dec_time / file_size


"""AES CBC mode"""
def AES_CBC(key_size , file_name , mode):
    """
    Args:
    key_size : Key size in bytes : 16 , 32, 
      
    file_name : File to encrypt in string format
     
    mode : AES mode , CTR, CBC, EBC, 
    """
    if file_name == "package_1":
        size = "1KB"
        file_size = 1000
    elif file_name =="package_2":
        size = "10MB"
        file_size = 10485760
    with open(file_name,'rb') as f_obj:
        plaintext_bytes = f_obj.read()

    print(f"{'-'*20}")
    print("\n\nOriginal message slice: ",plaintext_bytes[0:10])
    # Encryption
    start_key_time = time_ns()
    key_AES = get_random_bytes(key_size)
    end_key_time = time_ns()

    # Instantiate CBC object
    cipher_AES_CBC  = AES.new(key_AES, mode, use_aesni=True)

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
        decipher_AES_CBC = AES.new(key_AES, mode, iv,use_aesni=True)

        start_dec_time = time_ns()
        plaintext_text_with_pad = decipher_AES_CBC.decrypt(cipher_text)
        end_dec_time = time_ns()

        plaintext_text  = unpad(plaintext_text_with_pad,AES.block_size)
        print("The message was ",plaintext_text[:10])
    except (ValueError, KeyError):
        print("Incorrent decryption")



    #Key generation time
    key_gen_time = end_key_time - start_key_time

    enc_time = end_enc_time - start_enc_time 

    dec_time = end_dec_time - start_dec_time 

    if plaintext_text == plaintext_bytes:
        print("\n\nSUCCESS")

    per_byteenc = per_byte_enc(file_size, enc_time)
    per_bytedec = per_byte_dec(file_size, dec_time)

    return f"\n Filename: {file_name}:{size} KeyGen Time :{key_gen_time} ns ,Enc Time: {enc_time} ns, Dec Time: {dec_time} ns , Encryption speed per byte:{per_byteenc} ns, Decryption speed per byte:{per_bytedec} ns"

# print(f"{AES_CBC(16,'package_1',mode=AES.MODE_CBC)}")
# print(f"{AES_CBC(16,'package_2',mode=AES.MODE_CBC)}")
# print(f"{AES_CBC(32,'package_1',mode=AES.MODE_CBC)}")
# print(f"{AES_CBC(32,'package_2',mode=AES.MODE_CBC)}")
