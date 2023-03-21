"""DIGITAL SIGNATURE"""
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS
from Cryptodome.PublicKey import DSA
from time import time_ns

def per_byte_sign(size, sign_time):
    return size / sign_time

def per_byte_verify(size, verify_time):
    return size / verify_time


"""DSA SIGNING and VERIFICATION"""
def DSA_(key_size , file_name):

    if file_name == "package_1":
        size = "1KB"
        file_size = 1000
    elif file_name =="package_2":
        size = "10MB"
        file_size = 1048760
    with open(file_name,'rb') as f_obj:
        plaintext_bytes = f_obj.read()

    # Generate DSA key
    start_key_time = time_ns()
    key_DSA = DSA.generate(key_size)
    end_key_time = time_ns()

    # Save the public key
    f = open('public_key.pem','wb')
    f.write(key_DSA.publickey().export_key())
    f.close()

    # Instantiate the signer with private key
    signer = DSS.new(key_DSA,'fips-186-3')
    
    # Hash the plaintext
    hash_obj1 = SHA256.new(plaintext_bytes)

    # Sign the hashed message
    start_sign_time = time_ns()
    signature  = signer.sign(hash_obj1)
    end_sign_time  = time_ns()

    #Verification: Read the public key: Same file to be shared between signer and verifier
    f = open('public_key.pem','rb')
    
    # Import the public key
    pub_key = DSA.import_key(f.read())

    # Compute hash again
    hash_obj2 = SHA256.new(plaintext_bytes)

    #Instantiate the verfier with public key
    verifier = DSS.new(pub_key,'fips-186-3')

    # Verify the hashed message
    try:
        start_verify_time = time_ns()
        verifier.verify(hash_obj2, signature )
        end_verify_time = time_ns()
        print("\n\nThe message is authentic")
    except ValueError:
        print("\nThe message is not authentic")


    #Key time 
    key_gen_time = end_key_time - start_key_time

    sign_time =   end_sign_time - start_sign_time  

    verify_time = end_verify_time - start_verify_time 

    perbyte_sign = per_byte_sign(file_size, sign_time)
    perbyte_ver = per_byte_verify(file_size, verify_time)

    return f"Filename: {file_name}:{size}  , Keysize:{key_size} bits, KeyGen Time :{key_gen_time} ns, Sign Time: {sign_time} ns, Verify Time: {verify_time} ns, Per Byte Sign time: {perbyte_sign}, Per Byte Verify time: {perbyte_ver}"
        


# print(f"{DSA_(2048,'package_1')}")
# print(f"{DSA_(2048,'package_2')}")
# print(f"{DSA_(3072,'package_1')}")
# print(f"{DSA_(3072,'package_2')}")