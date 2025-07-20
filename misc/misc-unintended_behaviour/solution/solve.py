from pwn import connect
from base64 import b64encode

with open("config.json", "rb") as f:
    config_content = f.read()
    
with open("metadata.json", "rb") as f:
    metadata_content = f.read()
    
with open("model.weights.h5", "rb") as f:
    weights_content = f.read()

r = connect("localhost", 1337)

r.sendlineafter(b"Enter base64 encoded config file: ", b64encode(config_content))
r.sendlineafter(b"Enter base64 encoded metadata file: ", b64encode(metadata_content))
r.sendlineafter(b"Enter base64 encoded weights file: ", b64encode(weights_content))


r.interactive()