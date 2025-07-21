t = {
    ";": "provola",
    "+": "pROVOLA",
    "-": "prOVOLA",
    "*": "proVOLA",
    "/": "provOLA",
    "^": "provoLA",
    "@": "prOVOla",
    "cmp": "pRoVOLA",
    "jmp": "prOvOLA",
    "jp": "pr0VoLA",
    "label": "PRovOLA",
    "call": "PrOVOLA",
    "ret": "ProVOLA",
    "syscall": "provOLa",
    "reg0": "Provola",
    "reg1": "pRovola",
    "reg2": "prOvola",
    "reg3": "proVola",
    "reg4": "provOla",
    "reg5": "provoLa",
    "reg6": "provolA",
}

alphabet = "_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _:{}?"

flag = "toh{pr0v0l4ng_1s5_f45t3r_th4n_pyth0n}"


def compute_nums():
    for i in range(4, 35):
        a = ord(flag[i])
        b = ord(flag[i + 1])
        yield (a + b) ** 3

nums = list(compute_nums())[::-1]

print(nums)

def str_to_int(s):
    t = 0
    for c in s[::-1]:
        t = t * len(alphabet) + (alphabet[1:].index(c) + 1)
    if t >= 2**64:
        raise ValueError("Number too large")
    return t

code = (
    f"""
reg0 {str_to_int("Give me ")} ; reg0 ;
reg0 "printer" ; call ;
reg0 {str_to_int("the flag: ")} ; reg0 ;
reg0 "printer" ; call ;
reg1 "" ; reg0 1 ; syscall ;
reg0 "read_flag" ; call ;
reg1 0 ; reg1 ; reg0 0 ; reg0 ;
reg0 ; reg0 "cut_newline" ; call ;
reg1 0 ; reg1 ;
reg0 {str_to_int("Your input")} ; reg0 ;
reg0 "printer" ; call ;
reg0 {str_to_int(" was: ")} ; reg0 ;
reg0 "printer" ; call ;
reg0 1 ; syscall ;
reg3 reg1 ; reg0 1 ; reg1 10 ; reg2 1 ; syscall ;
reg0 {str_to_int("Now check")} ; reg0 ;
reg0 "printer" ; call ;
reg0 {str_to_int("ing it")} ; reg0 ;
reg0 "printer" ; call ;
reg0 1 ; reg1 46 ; reg2 1 ; syscall ; syscall ; syscall ;
reg1 32 ; syscall ;
reg3 ;
reg0 "check" ; call ;
reg0 0 ; reg0 ; reg0 - reg0 1 ;
reg1 "wrong flag" ; jp ;
reg0 "correct flag" ; jmp ;

reg0 "get_char" ; label ;
reg0 ; reg1 "{alphabet}" ; reg0 @ reg1 reg0 ; reg0 ;
ret ;

reg0 "printer" ; label ;
reg6 {len(alphabet)} ;
reg3 ; reg0 - reg3 * / reg3 reg6 reg6 ; reg4 reg0 ;
reg1 "printer_continues" ; jp ; ret ;
reg0 "printer_continues" ; label ;
reg4 ; reg0 "get_char" ; call ;
reg1 0 ; reg1 ; reg2 1 ; reg0 1 ; syscall ;
reg2 / reg3 {len(alphabet)} ;
reg0 cmp reg2 0 ; reg1 "printer_end" ; jp ;
reg2 ; reg0 "printer" ; call ;
reg0 "printer_end" ; label ; ret ;
ret ;

reg0 "correct flag" ; label ;
reg0 {str_to_int("correct")} ; reg0 ;
reg0 "printer" ; call ;
reg0 "end" ; jmp ;

reg0 "wrong flag" ; label ;
reg0 {str_to_int("wrong")} ; reg0 ;
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
reg3 ; reg4 ; reg0 "cubo di binomio" ; call ;
reg0 ^ cmp reg2 34 1 ; reg1 "check_inner" ; jp ;
reg2 1 ;
{"\n".join([f'reg1 {x} ; reg1 ; reg0 "eq" ; call ; reg1 0 ; reg1 ; reg1 - reg1 1 ; reg2 + reg2 reg1 ;' for x in nums])}
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

reg0 "cubo" ; label ;
reg5 ; reg6 reg5 ; reg4 reg6 ; reg3 0 ;
reg0 "cubo_start" ; label ;
reg3 + reg3 reg4 ;
reg0 ^ cmp reg6 1 1 ; reg6 - reg6 1 ; reg1 "cubo_start" ; jp ;
reg5 - reg5 1 ; reg6 reg4 ; reg0 ^ cmp reg5 0 1 ; reg1 "cubo_start" ; jp ;
reg3 ;
ret ;

reg0 "cubo di binomio" ; label ;
reg1 ; reg2 ;
reg1 ; reg0 "cubo" ; call ; reg3 ;
reg2 ; reg0 "cubo" ; call ; reg4 ;
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
"""[1:-1]
    .replace(" \n", "\n")
    .replace("\n", "\n\n")
    .replace("\n\n\n\n", "\n\n\n")
    .replace('"printer"', '"provola"')
    .replace('"get_char"', '"prOVOLA"')
    .replace('"printer_continues"', '"prOVOla"')
    .replace('"printer_end"', '"proVOLA"')
    .replace('"correct flag"', '"provOLA"')
    .replace('"wrong flag"', '"provOLa"')
    .replace('"end"', '"provoLA"')
    .replace('"read_flag"', '"provoLa"')
    .replace('"check"', '"provolA"')
    .replace('"cut_newline"', '"PROVOLA"')
    .replace('"cut_newline_start"', '"PrOVOLA"')
    .replace('"cut_newline_end"', '"PRovOLA"')
    .replace('"check_flag_bad"', '"PRovola"')
    .replace('"cubo"', '"PRovOLa"')
    .replace('"cubo_start"', '"PR0vOLa"')
    .replace('"cubo di binomio"', '"PR0VoLa"')
    .replace('"my_xor_1"', '"PrOVOLa"')
    .replace('"my_xor_2"', '"PrOVOla"')
    .replace('"my_xor_2_inner"', '"ProVOLA"')
    .replace('"eq"', '"prov0La"')
    .replace('"eq_1"', '"prov0lA"')
    .replace('"eq_end"', '"prov0LA"')
    .replace('"check_inner"', '"pr0v0lA"')
)

# split code by spaces, split the newlines by themselves
code = code.split(" ")
code = [x.split("\n") for x in code]
code = [item for sublist in code for item in sublist]
code = [x if x != "" else "\n" for x in code]

translation = ""

for word in code:
    # translate each word
    translation += word
    if word != "\n":
        translation += " "

# translation = translation.replace(" \n", "\n")

with open("chall.prvl", "w") as f:
    f.write(translation)
