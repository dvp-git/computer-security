
"""PKCS #1 OAEP"""
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP
from base64 import b64decode, b64encode
from time import time_ns

"""
ENCRYPTION:

# Split data into chunks
# Encrypt the chunk
# add it to cipherbytes object
"""

def per_byte_enc(size, enc_time):
    return  enc_time / size

def per_byte_dec(size, dec_time):
    return   dec_time / size


def RSA_(key_size,file_name):
    # Read the file
    if file_name == "package_1":
        size_repr = "1KB"
        file_size = 1000
    elif file_name =="file_rsa":
        size_repr = "10MB"
        file_size = 1048576

    with open(file_name,'rb') as f_obj:
        plaintext_bytes = f_obj.read()

    # Generate the RSA key
    start_key_time = time_ns()
    key = RSA.generate(key_size)
    end_key_time = time_ns()


    # Save pvt key file with a secret key
    secret_code = "S@cret123_4"
    private_key = key.export_key(passphrase=secret_code)

    # Save the private key in file privateRSA.pem
    file_out = open("privateRSA.pem","wb")
    file_out.write(private_key)
    file_out.close()

    # Save public key file in file publicRSA.pem
    public_key = key.publickey().export_key()
    file_out = open("publicRSA.pem","wb")
    file_out.write(public_key)
    file_out.close()

    # Encrypt file 
    file_out = open("encrypted_data.bin","wb")

    # Use public key for encryption
    public_enc_key = open("publicRSA.pem").read()

    # Use public key for encryption
    recipient_key = RSA.import_key(public_enc_key)


    # Instantiate PKCS object
    cipher_RSA  = PKCS1_OAEP.new(recipient_key)
    start_enc_time = 0
    end_enc_time = 0
    ciphertext_bytes = b''
    # print(plaintext_bytes)
    for i in range(0,len(plaintext_bytes),190):
        content_ = plaintext_bytes[i:i+190]
        #print(f"\nContent chunk: {len(content_)}")
        start_enc_time += time_ns()
        ciphertext_bytes += cipher_RSA.encrypt(content_)
        end_enc_time += time_ns()
        # print(f"\n Encrypted : {b64encode(ciphertext_bytes).decode('utf-8')}")

        #print(f"\n Encrypted length {len(ciphertext_bytes)}")

    # print("Encrypted Cyphertext : ",ciphertext_bytes, len(ciphertext_bytes))
    #print(f"\n{b64encode(ciphertext_bytes).decode('utf-8')}")
    #print(f"{len(b64encode(ciphertext_bytes).decode('utf-8'))}")

    #Save the encrypted file
    file_out.write(ciphertext_bytes)
    file_out.close()

    """
    DECRYPTION:

    # Decrypt each piece of data 
    # Combine the result to the plaintext object
    """
    with open('encrypted_data.bin','rb') as f_obj:
        ciphertext_bytes_2 = f_obj.read()



    # Read private key from saved file
    private_dec_key = open("privateRSA.pem").read()

    # Import private key for decryption
    recipient_pvt_key = RSA.import_key(private_dec_key,passphrase=secret_code)

    # Instantiate PKCS object with private key
    decipher_RSA  = PKCS1_OAEP.new(recipient_pvt_key)



    # Instantiate the plaintext bytes object
    plaintext_receiver_bytes = b''
    # print(ciphertext_bytes)
    start_dec_time = 0
    end_dec_time = 0
    
    if key_size == 2048:
        chunk_size = 256
    elif key_size == 3072:
        chunk_size = 384
    # Each chunk has a maximum size of 256 bytes ciphertext
    for i in range(0,len(ciphertext_bytes_2),chunk_size):
        content_d = ciphertext_bytes_2[i:i+chunk_size]
        # print(f"\nContent chunk: {len(content_d)}")
        start_dec_time += time_ns()
        plaintext_receiver_bytes += decipher_RSA.decrypt(content_d)
        # print(f"Length of content d {content_d}")
        end_dec_time += time_ns()
        # print(f"\n Decrypted : {(plaintext_receiver_bytes).decode('utf-8')}")
        #print(f"\n Decrypted length {len(plaintext_receiver_bytes)}")

    # print(f"\n{content_d}")

    #Key generation time
    key_gen_time = end_key_time - start_key_time

    enc_time = end_enc_time - start_enc_time 

    dec_time = end_dec_time - start_dec_time 

    if plaintext_receiver_bytes == plaintext_bytes:
        print("\n\nSUCCESS")


    # print(f"\n{(plaintext_receiver_bytes).decode('utf-8')}")
    # print(f"{len((plaintext_receiver_bytes).decode('utf-8'))}")

    per_byteenc = per_byte_enc(file_size,enc_time)
    per_bytedec = per_byte_dec(file_size,dec_time)

    return f"\n Filename: {file_name}:{size_repr} KeyGen Time :{key_gen_time} ns,Enc Time: {enc_time} ns, Dec Time: {dec_time} ns ,Encryption speed per byte:{per_byteenc}, Decryption speed per byte:{per_bytedec}"



# print(f"{RSA_(2048,'package_1')}")
# print(f"{RSA_(2048,'file_rsa')}")
# print(f"{RSA_(3072,'package_1')}")
# print(f"{RSA_(3072,'file_rsa')}")
