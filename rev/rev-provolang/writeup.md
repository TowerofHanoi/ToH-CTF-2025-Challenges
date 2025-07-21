## Challenge Description
Who said provolas do not make for a great programming language?
No one, actually

## Challenge Files
Two files were given:
- `provolang`: the interpreter of the "PROVOLA" esoteric language.
- `chall.prvl`: the challenge file written in "PROVOLA".

## Challenge Behavior
```bash
➜  chall ./provolang chall.prvl
Give me the flag: flag{provola}
Your input was: flag{provola}
Now checking it... wrong!
```

## Walkthrough
We can run `file provolang` to inspect it:
```bash
➜  chall file provolang
provolang: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cbc4433fe48108ebae014e3c3886a6edd5ac2d48, for GNU/Linux 3.2.0, stripped
```

It is a stripped ELF binary, but from strings we can see the following:
```bash
-➜  chall strings provolang
[...]
__gmon_start__
PROVOLA Interpreter v1.0
Usage: %s <filename>
provola
PRovOLA
PrOVOLA
ProVOLA
provOLa
prOvOLA
pr0VoLA
pROVOLA
prOVOLA
proVOLA
provOLA
provoLA
pRoVOLA
prOVOla
;*3$"
GCC: (GNU) 14.2.1 20250110 (Red Hat 14.2.1-7)
[...]
```

Cross-referencing the strings with the contents of `chall.prvl`, we can probably deduce that provolang is a case-sensitive language where each instruction/opcode is a variation of the word "provola" with different capitalizations, and possibly some leetcode substitutions.

Given that the interpreter is stripped, a good approach to reverse-engineer how it works is to perform dynamic analysis to identify which instructions correspond to the execution of the different functions of the program. Another good entrypoint is to look for input/output functions, as provolang has the ability to ask for user input and can print to stdout.

We intentionally kept the whitespace between the different functions in `chall.prvl`, even if not necessary at all for the code to run, just to make it easier to read and inspect.

For example, we can remove most of the code in `chall.prvl` and the interpreter will still run and print the initial message. 
With some static analysis and some debugging, we can identify a mapping between the provolang instructions and some more common names for them:
- `provola` -> `;`, or line terminator
- `pROVOLA` -> `+`,
- `prOVOLA` -> `-`
- `proVOLA` -> `*`
- `provOLA` -> `/`
- `provoLA` -> `^`
- `prOVOla` -> `@`
- `pRoVOLA` -> `cmp`
- `prOvOLA` -> `jmp`
- `pr0VoLA` -> `jp`
- `PRovOLA` -> `label`
- `PrOVOLA` -> `call`
- `ProVOLA` -> `ret`
- `provOLa` -> `syscall`

Additionally, we can identify a set of registers that are used by the interpreter:
- `Provola` -> `reg0`
- `pRovola` -> `reg1`
- `prOvola` -> `reg2`
- `proVola` -> `reg3`
- `provOla` -> `reg4`
- `provoLa` -> `reg5`
- `provolA` -> `reg6`

Reversing the interpreter in its entirety was not really necessary to solve the challenge. The interesting constants in the code sort of hint to where the flag check is actually happening: even from the bare `provolang` code, the flag format check can be identified in the following lines:
```
pRovola prOVOla Provola 0 provola pRovola provoLA pRoVOLA pRovola 116 1 provola Provola provola Provola pRovola provola pRovola "PRovola" provola pr0VoLA provola Provola 0 provola Provola provola
pRovola prOVOla Provola 1 provola pRovola provoLA pRoVOLA pRovola 111 1 provola Provola provola Provola pRovola provola pRovola "PRovola" provola pr0VoLA provola Provola 0 provola Provola provola
pRovola prOVOla Provola 2 provola pRovola provoLA pRoVOLA pRovola 104 1 provola Provola provola Provola pRovola provola pRovola "PRovola" provola pr0VoLA provola Provola 0 provola Provola provola
pRovola prOVOla Provola 3 provola pRovola provoLA pRoVOLA pRovola 123 1 provola Provola provola Provola pRovola provola pRovola "PRovola" provola pr0VoLA provola Provola 0 provola Provola provola
pRovola prOVOla Provola 36 provola pRovola provoLA pRoVOLA pRovola 125 1 provola Provola provola Provola pRovola provola pRovola "PRovola" provola pr0VoLA provola Provola 0 provola Provola provola
```
Converting `[116, 111, 104, 123, 125]` to ASCII simply gives us the string `toh{}`, therefore it is likely that the rest of the flag checking is performed in code that is right after this snippet.

If we convert the `chall.prvl` to the equivalent but readable opcode scheme, and assign some sensible labels to the functions (or ask ChatGPT to do it for us), we get the following:
```
reg0 469681607912613 ; reg0 ; 
reg0 "printer" ; call ; 
reg0 2266930679295194654 ; reg0 ; 
reg0 "printer" ; call ; 
reg1 "" ; reg0 1 ; syscall ; 
reg0 "read_flag" ; call ; 
reg1 0 ; reg1 ; reg0 0 ; reg0 ; 
reg0 ; reg0 "cut_newline" ; call ; 
reg1 0 ; reg1 ; 
reg0 719952190591175592 ; reg0 ; 
reg0 "printer" ; call ; 
reg0 100013585934 ; reg0 ; 
reg0 "printer" ; call ; 
reg0 1 ; syscall ; 
reg3 reg1 ; reg0 1 ; reg1 10 ; reg2 1 ; syscall ; 
reg0 5674673370347023 ; reg0 ; 
reg0 "printer" ; call ; 
reg0 31505361438 ; reg0 ; 
reg0 "printer" ; call ; 
reg0 1 ; reg1 46 ; reg2 1 ; syscall ; syscall ; syscall ; 
reg1 32 ; syscall ; 
reg3 ; 
reg0 "check" ; call ; 
reg0 0 ; reg0 ; reg0 - reg0 1 ; 
reg1 "wrong flag" ; jp ; 
reg0 "correct flag" ; jmp ; 

reg0 "get_char" ; label ; 
reg0 ; reg1 "_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _:{}?" ; reg0 @ reg1 reg0 ; reg0 ; 
ret ; 

reg0 "printer" ; label ; 
reg6 69 ; 
reg3 ; reg0 - reg3 * / reg3 reg6 reg6 ; reg4 reg0 ; 
reg1 "printer_continues" ; jp ; ret ; 
reg0 "printer_continues" ; label ; 
reg4 ; reg0 "get_char" ; call ; 
reg1 0 ; reg1 ; reg2 1 ; reg0 1 ; syscall ; 
reg2 / reg3 69 ; 
reg0 cmp reg2 0 ; reg1 "printer_end" ; jp ; 
reg2 ; reg0 "printer" ; call ; 
reg0 "printer_end" ; label ; ret ; 
ret ; 

reg0 "correct flag" ; label ; 
reg0 2163174691170 ; reg0 ; 
reg0 "printer" ; call ; 
reg0 "end" ; jmp ; 

reg0 "wrong flag" ; label ; 
reg0 163341653 ; reg0 ; 
reg0 "printer" ; call ; 
reg0 "end" ; jmp ; 

reg0 "end" ; label ; 
reg0 1 ; reg1 33 ; reg2 1 ; syscall ; reg1 10 ; syscall ; 
reg0 0 ; syscall ; 

reg0 "read_flag" ; label ; 
reg1 64 ; reg0 2 ; syscall ; 
reg0 ; reg1 ; 
ret ; 

reg0 "check" ; label ; 
reg0 ; 
reg1 @ reg0 0 ; reg1 ^ cmp reg1 116 1 ; reg0 ; reg0 reg1 ; reg1 "check_flag_bad" ; jp ; reg0 0 ; reg0 ; 
reg1 @ reg0 1 ; reg1 ^ cmp reg1 111 1 ; reg0 ; reg0 reg1 ; reg1 "check_flag_bad" ; jp ; reg0 0 ; reg0 ; 
reg1 @ reg0 2 ; reg1 ^ cmp reg1 104 1 ; reg0 ; reg0 reg1 ; reg1 "check_flag_bad" ; jp ; reg0 0 ; reg0 ; 
reg1 @ reg0 3 ; reg1 ^ cmp reg1 123 1 ; reg0 ; reg0 reg1 ; reg1 "check_flag_bad" ; jp ; reg0 0 ; reg0 ; 
reg1 @ reg0 36 ; reg1 ^ cmp reg1 125 1 ; reg0 ; reg0 reg1 ; reg1 "check_flag_bad" ; jp ; reg0 0 ; reg0 ; 
reg5 reg0 ; 
reg2 3 ; 
reg0 "check_inner" ; label ; 
reg2 + reg2 1 ; 
reg3 @ reg5 reg2 ; reg4 @ reg5 + reg2 1 ; 
reg3 ; reg4 ; reg0 "cube_of_a_binomial" ; call ; 
reg0 ^ cmp reg2 34 1 ; reg1 "check_inner" ; jp ; 
reg2 1 ; 
reg1 3944312 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 3511808 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 10648000 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 13312053 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 12649337 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 8869743 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 8615125 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 4251528 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 3796416 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 10648000 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 9393931 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 9129329 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 4492125 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 4657463 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 4826809 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 1157625 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 3652264 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 7645373 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 3241792 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 4741632 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 4410944 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 2985984 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 7762392 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 9663597 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 4251528 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 4096000 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 3796416 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 4574296 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 4574296 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 4251528 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg1 11543176 ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ; 
reg2 ; 
ret ; 

reg0 "check_flag_bad" ; label ; 
reg0 2 ; reg0 ; 
ret ; 

reg0 "cut_newline" ; label ; 
reg4 ; reg3 0 ; 
reg0 "cut_newline_start" ; label ; 
reg2 @ reg4 reg3 ; 
reg0 cmp reg2 10 ; 
reg1 "cut_newline_end" ; jp ; 
reg3 + reg3 1 ; 
reg0 "cut_newline_start" ; jmp ; 
reg0 "cut_newline_end" ; label ; 
reg0 - reg4 reg3 ; reg0 ; 
ret ; 

reg0 "cube" ; label ; 
reg5 ; reg6 reg5 ; reg4 reg6 ; reg3 0 ; 
reg0 "cube_start" ; label ; 
reg3 + reg3 reg4 ; 
reg0 ^ cmp reg6 1 1 ; reg6 - reg6 1 ; reg1 "cube_start" ; jp ; 
reg5 - reg5 1 ; reg6 reg4 ; reg0 ^ cmp reg5 0 1 ; reg1 "cube_start" ; jp ; 
reg3 ; 
ret ; 

reg0 "cube_of_a_binomial" ; label ; 
reg1 ; reg2 ; 
reg1 ; reg0 "cube" ; call ; reg3 ; 
reg2 ; reg0 "cube" ; call ; reg4 ; 
reg0 + reg3 + * * 3 * reg1 reg1 reg2 + * * 3 * reg1 reg2 reg2 reg4 ; 
reg0 ; ret ; 

reg0 "my_xor_1" ; label ; 
reg0 ; reg1 ; reg6 2 ; 
reg0 ^ cmp / + * reg0 / reg0 reg1 * reg1 / reg1 reg0 reg6 reg0 1 ; reg0 + reg0 1 ; reg0 ; 
ret ; 

reg0 "my_xor_2" ; label ; 
reg5 ; reg1 ; reg6 256 ; 
reg2 - reg5 * / reg5 reg6 reg6 ; reg2 + reg2 1 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; reg3 + reg3 1 ; 
reg2 ; reg3 ; reg0 "my_xor_2_inner" ; call ; reg2 0 ; reg2 ; reg2 - reg2 1 ; 
reg4 + * reg4 reg6 reg2 ; 
reg5 / reg5 reg6 ; 
reg1 / reg1 reg6 ; 
reg2 - reg5 * / reg5 reg6 reg6 ; reg2 + reg2 1 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; reg3 + reg3 1 ; 
reg2 ; reg3 ; reg0 "my_xor_2_inner" ; call ; reg2 0 ; reg2 ; reg2 - reg2 1 ; 
reg4 + * reg4 reg6 reg2 ; 
reg5 / reg5 reg6 ; 
reg1 / reg1 reg6 ; 
reg2 - reg5 * / reg5 reg6 reg6 ; reg2 + reg2 1 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; reg3 + reg3 1 ; 
reg2 ; reg3 ; reg0 "my_xor_2_inner" ; call ; reg2 0 ; reg2 ; reg2 - reg2 1 ; 
reg4 + * reg4 reg6 reg2 ; 
reg5 / reg5 reg6 ; 
reg1 / reg1 reg6 ; 
reg2 - reg5 * / reg5 reg6 reg6 ; reg2 + reg2 1 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; reg3 + reg3 1 ; 
reg2 ; reg3 ; reg0 "my_xor_2_inner" ; call ; reg2 0 ; reg2 ; reg2 - reg2 1 ; 
reg4 + * reg4 reg6 reg2 ; 
reg5 / reg5 reg6 ; 
reg1 / reg1 reg6 ; 
reg2 - reg5 * / reg5 reg6 reg6 ; reg2 + reg2 1 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; reg3 + reg3 1 ; 
reg2 ; reg3 ; reg0 "my_xor_2_inner" ; call ; reg2 0 ; reg2 ; reg2 - reg2 1 ; 
reg4 + * reg4 reg6 reg2 ; 
reg5 / reg5 reg6 ; 
reg1 / reg1 reg6 ; 
reg2 - reg5 * / reg5 reg6 reg6 ; reg2 + reg2 1 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; reg3 + reg3 1 ; 
reg2 ; reg3 ; reg0 "my_xor_2_inner" ; call ; reg2 0 ; reg2 ; reg2 - reg2 1 ; 
reg4 + * reg4 reg6 reg2 ; 
reg5 / reg5 reg6 ; 
reg1 / reg1 reg6 ; 
reg2 - reg5 * / reg5 reg6 reg6 ; reg2 + reg2 1 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; reg3 + reg3 1 ; 
reg2 ; reg3 ; reg0 "my_xor_2_inner" ; call ; reg2 0 ; reg2 ; reg2 - reg2 1 ; 
reg4 + * reg4 reg6 reg2 ; 
reg5 / reg5 reg6 ; 
reg1 / reg1 reg6 ; 
reg2 - reg5 * / reg5 reg6 reg6 ; reg2 + reg2 1 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; reg3 + reg3 1 ; 
reg2 ; reg3 ; reg0 "my_xor_2_inner" ; call ; reg2 0 ; reg2 ; reg2 - reg2 1 ; 
reg4 + * reg4 reg6 reg2 ; 
reg4 + reg4 1 ; reg4 ; 
ret ; 

reg0 "my_xor_2_inner" ; label ; 
reg0 ; reg1 ; reg6 2 ; 
reg0 - reg0 1 ; reg1 - reg1 1 ; 
reg2 - reg0 * / reg0 reg6 reg6 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; 
reg4 ^ cmp reg2 reg3 1 ; 
reg0 / reg0 reg6 ; 
reg1 / reg1 reg6 ; 
reg2 - reg0 * / reg0 reg6 reg6 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; 
reg4 + reg4 * ^ cmp reg2 reg3 1 reg6 ; 
reg0 / reg0 reg6 ; 
reg1 / reg1 reg6 ; 
reg2 - reg0 * / reg0 reg6 reg6 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; 
reg4 + reg4 * ^ cmp reg2 reg3 1 * reg6 reg6 ; 
reg0 / reg0 reg6 ; 
reg1 / reg1 reg6 ; 
reg2 - reg0 * / reg0 reg6 reg6 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; 
reg4 + reg4 * ^ cmp reg2 reg3 1 * reg6 * reg6 reg6 ; 
reg0 / reg0 reg6 ; 
reg1 / reg1 reg6 ; 
reg2 - reg0 * / reg0 reg6 reg6 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; 
reg4 + reg4 * ^ cmp reg2 reg3 1 * * reg6 reg6 * reg6 reg6 ; 
reg0 / reg0 reg6 ; 
reg1 / reg1 reg6 ; 
reg2 - reg0 * / reg0 reg6 reg6 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; 
reg4 + reg4 * ^ cmp reg2 reg3 1 * * reg6 reg6 * reg6 * reg6 reg6 ; 
reg0 / reg0 reg6 ; 
reg1 / reg1 reg6 ; 
reg2 - reg0 * / reg0 reg6 reg6 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; 
reg4 + reg4 * ^ cmp reg2 reg3 1 * * reg6 reg6 * reg6 * reg6 * reg6 reg6 ; 
reg0 / reg0 reg6 ; 
reg1 / reg1 reg6 ; 
reg2 - reg0 * / reg0 reg6 reg6 ; 
reg3 - reg1 * / reg1 reg6 reg6 ; 
reg4 + reg4 * ^ cmp reg2 reg3 1 * * reg6 reg6 * reg6 * reg6 * reg6 * reg6 reg6 ; 
reg4 + reg4 1 ; reg4 ; 
ret ; 

reg0 "eq" ; label ; 
reg0 ; reg1 ; 
reg2 reg0 ; reg3 reg1 ; 
reg2 - reg0 * / reg0 2 2 ; 
reg3 reg0 ; reg4 reg1 ; 
reg0 reg2 ; reg1 "eq_1" ; jp ; 
reg3 ; reg4 ; reg0 "my_xor_2" ; call ; 
reg0 "eq_end" ; jmp ; 
reg0 "eq_1" ; label ; 
reg3 ; reg4 ; reg0 "my_xor_1" ; call ; 
reg0 "eq_end" ; label ; 
ret ; 
```

The challenge file is performing the following mathematical operations:
- It sums the ASCII values of the characters in the flag two at a time.
- It calculates the cube of the sum, using the formula for the cube of a binomial.
- It then checks if the result matches the predefined constants, in reverse order with respect to the flag characters, as pushing and popping elements on a stack invertes the order.

For example, for the flag `toh{abcd}`, it calculates:
- `(ord('a') + ord('b')) ^ 3`
- `(ord('b') + ord('c')) ^ 3`
- ...

To make side channels involving counting the number of executed instruction harder, the interpreter uses a custom XOR operation that switches between two different implementations at runtime.
Some other operations are also obfuscated in provolang, such as the cube operation.

Once we have identified the mathematical flag checking operation, we can write a Python script to calculate the flag that would pass the check. A simple way to do it is to extract the cube root of each of the constants and then brute-force the first flag character: the rest of the flag is then calculated char-by-char by subtracting the ASCII value of the previous character from the current one.
```py
vals = [
    3944312, 3511808, 10648000, 13312053, 12649337, 8869743, 8615125, 4251528, 3796416, 10648000, 9393931, 9129329, 4492125, 4657463, 4826809, 1157625, 3652264, 7645373, 3241792, 4741632, 4410944, 2985984, 7762392, 9663597, 4251528, 4096000, 3796416, 4574296, 4574296, 4251528, 11543176,
]

sums = [round(pow(v, 1/3)) for v in vals]

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _:{}?"

for c in range(32, 127):
    try:
        print(chr(c), end=': toh{')
        print(chr(c), end='')
        base = c
        for s in sums[::-1]:
            x = s - base
            if chr(x) not in charset:
                print()
                raise ValueError("Invalid character")
            base = x
            print(chr(x), end='')
        print('}')
    except:
        pass
```
This script will output all the possible flags that pass the check, and we can see that:
```bash
p: toh{pr0v0l4ng_1s5_f45t3r_th4n_pyth0n}
```
is the only valid flag returned.