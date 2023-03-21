
from Cryptodome.Hash import SHA256, SHA512, SHA3_256
from time import time_ns

def per_byte_hash(file_size, hash_time):
    return hash_time / file_size

"""HASHING"""
def sha_(bit_size,file_name):
    """
    Args: 
    """
    if file_name == "package_1":
        size = "1KB"
        file_size = 1000
    elif file_name =="package_2":
        size = "10MB"
        file_size = 1048760
    with open(file_name,'rb') as f_obj:
        plaintext_bytes = f_obj.read()
    

    # Hashing
    if bit_size == '256':
        h = SHA256.new()
    elif bit_size == '512':
        h = SHA512.new()
    elif bit_size == '3-256':
        h = SHA3_256.new()
        
    start_hash_time = time_ns()
    hash_object = h.update(plaintext_bytes)
    end_hash_time = time_ns()
    
    #print(f"\n\n{h.hexdigest()}")
    hash_time  = end_hash_time - start_hash_time
    per_byte_hash_time = per_byte_hash(file_size, hash_time)
    return f"\n Hashing function : SHA-{bit_size} Filename: {file_name}:{size} Hash Time :{hash_time} ns , Per-Byte-Hash : {per_byte_hash_time} "

# print(f"{sha_('256','package_1')}")
# print(f"{sha_('256','package_2')}")


# print(f"{sha_('512','package_1')}")
# print(f"{sha_('512','package_2')}")


# print(f"{sha_('3-256','package_1')}")
# print(f"{sha_('3-256','package_2')}")
