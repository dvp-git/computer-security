from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP


key = RSA.generate(2048)

private_key = key.export_key()
file_out = open("private_sample.pem", "wb")
file_out.write(private_key)
file_out.close()

public_key = key.publickey().export_key()
file_out = open("receiver_sample.pem", "wb")
file_out.write(public_key)
file_out.close()

data = b"I met aliens in UFO. Here issdasdasdasdasdasdasdasd the map."

recipient_key = RSA.import_key(open("receiver_sample.pem").read())

# Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(recipient_key)


ciphertext = cipher_rsa.encrypt(data)
print(len(ciphertext))


