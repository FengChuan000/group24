import base64
from Crypto.Hash import SHA1
from Crypto.Hash import SHA256
import random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random

import socket
def hash_function1(data):
    digest=SHA1.new()
    digest.update(data)
    return(digest)
def hash_function2(data):
    digest=SHA256.new()
    digest.update(data)
    return(digest)

s1 = socket.socket() 
host = socket.gethostname() 
port = 12345
s1.connect((host, port))
print("链接成功")
p = s1.recv(1024)
signature = s1.recv(1024)
signature=signature
print("收到p和sig：",p,signature)


d1=2100-2000
current_hash=hash_function2(p)
hash_chain3 = [current_hash]
for i in range(1, d1):
    current_hash = hash_function2(current_hash.digest())
    hash_chain3.append(current_hash)
c1=hash_chain3[-1]
with open('public_key.pem') as f:
    key=f.read()
    unsignkey=RSA.importKey(key)
    unsigner=Signature_pkcs1_v1_5.new(unsignkey)
    is_verify = unsigner.verify(c1, base64.b64decode(signature))
    print("Bob 验证 Alice's proof:",is_verify)

