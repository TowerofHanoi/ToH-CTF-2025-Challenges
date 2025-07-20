/**
 * @mebeim - 2025-04-06
 */

#pragma once

#include <stdint.h>

#ifndef __ORDER_LITTLE_ENDIAN__
#error "Must compile for little endian!"
#endif

#define XSTR(x) #x
#define STR(x) XSTR(x)

#define ASM_PREPARE_PARAMS0
#define ASM_PREPARE_PARAMS1 "mr 3,%[a1]\n\t"
#define ASM_PREPARE_PARAMS2 "mr 4,%[a2]\n\t" ASM_PREPARE_PARAMS1
#define ASM_PREPARE_PARAMS3 "mr 5,%[a3]\n\t" ASM_PREPARE_PARAMS2
#define ASM_PREPARE_PARAMS4 "mr 6,%[a4]\n\t" ASM_PREPARE_PARAMS3
#define ASM_PREPARE_PARAMS5 "mr 7,%[a5]\n\t" ASM_PREPARE_PARAMS4
#define ASM_PREPARE_PARAMS6 "mr 8,%[a6]\n\t" ASM_PREPARE_PARAMS5
#define ASM_PREPARE_PARAMS7 "mr 9,%[a7]\n\t" ASM_PREPARE_PARAMS6
#define ASM_PREPARE_PARAMS(n) ASM_PREPARE_PARAMS##n

#define ASM_GET_RESULT0
#define ASM_GET_RESULT1 "mr %[res],3\n\t"
#define ASM_GET_RESULT(n) ASM_GET_RESULT##n

/* Function calls from big endian functions need the func ptr to be byte swapped
 * if it is read from memory at runtime (e.g. GOT entries for library funcs).
 * Not really used in this final version of the chall.
 */
#define ASM_CALL_FPTR0    \
    "mtctr   %[fptr]\n\t" \
    "bctrl          \n\t"
#define ASM_CALL_FPTR1               \
    "srdi    8,%[fptr],32      \n\t" \
    "rotlwi  10,%[fptr],24     \n\t" \
    "rlwimi  10,%[fptr],8,8,15 \n\t" \
    "rlwimi  10,%[fptr],8,24,31\n\t" \
    "rotlwi  7,8,24            \n\t" \
    "rlwimi  7,8,8,8,15        \n\t" \
    "rlwimi  7,8,8,24,31       \n\t" \
    "sldi    10,10,32          \n\t" \
    "or      10,10,7           \n\t" \
    "mtctr   10                \n\t" \
    "bctrl                     \n\t"
#define ASM_CALL_FPTR(bswap_fptr) ASM_CALL_FPTR##bswap_fptr

#define BE(code) \
    ".start_be_insns%=" STR(__COUNTER__) ":\n\t" \
    code                                         \
    ".end_be_insns%=" STR(__COUNTER__) ":  \n\t"

#define ASM_BODY_BE(bswap_fptr, has_retval, nargs, func, ...) \
        ".start_asm_wrapped_call%=: \n\t"                     \
        /* Figure out if we are running in LE or BE */        \
        "    tdi     0,0,0x48        \n\t" /* [BE] b +8 */    \
        "    b       .le%=           \n\t"                    \
    BE(                                                       \
        "    stdu    1,-512(1)       \n\t"                    \
        ASM_PREPARE_PARAMS(nargs)                             \
        ASM_CALL_FPTR(bswap_fptr)                             \
        ASM_GET_RESULT(has_retval)                            \
        "    addi    1,1,512         \n\t"                    \
        "    b       .done%=         \n\t"                    \
    )                                                         \
        ".le%=:                      \n\t"                    \
        "    stdu    1,-512(1)       \n\t"                    \
        /* Switch to BE */                                    \
        "    li      0,363           \n\t"                    \
        "    sc                      \n\t"                    \
        "    tdi     0,0,0x48        \n\t" /* [BE] b +8 */    \
        "    b       .fail_le%=      \n\t"                    \
    BE(                                                       \
        /* Invoke function and save return value */           \
        ASM_PREPARE_PARAMS(nargs)                             \
        ASM_CALL_FPTR(bswap_fptr)                             \
        ASM_GET_RESULT(has_retval)                            \
        /* Switch back to LE */                               \
        "    li      0,363           \n\t"                    \
        "    sc                      \n\t"                    \
        "    tdi     0,0,0x48        \n\t" /* [LE] b +8 */    \
        "    b       .fail_be%=      \n\t"                    \
    )                                                         \
        "    addi    1,1,512         \n\t"                    \
        "    b       .done%=         \n\t"                    \
    BE(                                                       \
        ".fail_be%=:                 \n\t"                    \
        "    li      3,1             \n\t"                    \
        "    li      0,234           \n\t"                    \
        "    sc                      \n\t"                    \
        "    b       .fail_be%=      \n\t"                    \
    )                                                         \
        ".fail_le%=:                 \n\t"                    \
        "    li      3,1             \n\t"                    \
        "    li      0,234           \n\t"                    \
        "    sc                      \n\t"                    \
        "    b       .fail_le%=      \n\t"                    \
        ".done%=:                    \n\t"                    \
        ".end_asm_wrapped_call%=:    \n\t"

#define ASM_BODY_LE(bswap_fptr, has_retval, nargs, func, ...) \
        ".start_asm_wrapped_call%=: \n\t"                     \
        /* Figure out if we are running in LE or BE */        \
    BE(                                                       \
        "    tdi     0,0,0x48        \n\t" /* [LE] b +8 */    \
        "    b       .be%=           \n\t"                    \
    )                                                         \
        "    stdu    1,-512(1)       \n\t"                    \
        ASM_PREPARE_PARAMS(nargs)                             \
        ASM_CALL_FPTR(bswap_fptr)                             \
        ASM_GET_RESULT(has_retval)                            \
        "    addi    1,1,512         \n\t"                    \
        "    b       .done%=         \n\t"                    \
    BE(                                                       \
        ".be%=:                      \n\t"                    \
        "    stdu    1,-512(1)       \n\t"                    \
        /* Switch to BE */                                    \
        "    li      0,363           \n\t"                    \
        "    sc                      \n\t"                    \
        "    tdi     0,0,0x48        \n\t" /* [LE] b +8 */    \
        "    b       .fail_be%=      \n\t"                    \
    )                                                         \
        /* Invoke function and save return value */           \
        ASM_PREPARE_PARAMS(nargs)                             \
        ASM_CALL_FPTR(bswap_fptr)                             \
        ASM_GET_RESULT(has_retval)                            \
        /* Switch back to LE */                               \
        "    li      0,363           \n\t"                    \
        "    sc                      \n\t"                    \
        "    tdi     0,0,0x48        \n\t" /* [BE] b +8 */    \
        "    b       .fail_le%=      \n\t"                    \
    BE(                                                       \
        "    addi    1,1,512         \n\t"                    \
        "    b       .done%=         \n\t"                    \
        ".fail_be%=:                 \n\t"                    \
        "    li      3,1             \n\t"                    \
        "    li      0,234           \n\t"                    \
        "    sc                      \n\t"                    \
        "    b       .fail_be%=      \n\t"                    \
    )                                                         \
        ".fail_le%=:                 \n\t"                    \
        "    li      3,1             \n\t"                    \
        "    li      0,234           \n\t"                    \
        "    sc                      \n\t"                    \
        "    b       .fail_le%=      \n\t"                    \
        ".done%=:                    \n\t"                    \
        ".end_asm_wrapped_call%=:    \n\t"

#define ASM_INPUTS0(func, ...) \
    [fptr]"r"(func)
#define ASM_INPUTS1(func, a) \
    [fptr]"r"(func), [a1]"r"(a)
#define ASM_INPUTS2(func, a, b) \
    [fptr]"r"(func), [a1]"r"(a), [a2]"r"(b)
#define ASM_INPUTS3(func, a, b, c) \
    [fptr]"r"(func), [a1]"r"(a), [a2]"r"(b), [a3]"r"(c)
#define ASM_INPUTS4(func, a, b, c, d) \
    [fptr]"r"(func), [a1]"r"(a), [a2]"r"(b), [a3]"r"(c), [a4]"r"(d)
#define ASM_INPUTS5(func, a, b, c, d, e) \
    [fptr]"r"(func), [a1]"r"(a), [a2]"r"(b), [a3]"r"(c), [a4]"r"(d), \
    [a5]"r"(e)
#define ASM_INPUTS6(func, a, b, c, d, e, f) \
    [fptr]"r"(func), [a1]"r"(a), [a2]"r"(b), [a3]"r"(c), [a4]"r"(d), \
    [a5]"r"(e), [a6]"r"(f)
#define ASM_INPUTS7(func, a, b, c, d, e, f, g) \
    [fptr]"r"(func), [a1]"r"(a), [a2]"r"(b), [a3]"r"(c), [a4]"r"(d), \
    [a5]"r"(e), [a6]"r"(f), [a7]"r"(g)
#define ASM_INPUTS(n, func, ...) ASM_INPUTS##n(func, __VA_ARGS__)

/* Clobbered by switch_endian: r3, r9-12, cr0-1, cr5-7, xer, ctr.
 * Since GCC cannot track calls via inline asm, clobber any volatile register
 * except r1 (stack pointer) to be safe, as well as the link register and flags.
 * We technically also use r1, but don't report it as clobbered since we restore
 * it. */
#define ASM_CLOBBERS                                                      \
    "r0", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",  \
    "r13", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9",    \
    "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", \
    "cr0", "cr1", "cr5", "cr6", "cr7", "xer", "ctr", "cc", "lr", "memory"

#define FUNC_PARAM(type, name) type name

#ifdef TEST

#define MAGIC_CALLn(bswap_fptr, endian, nargs, func, ...) ({(func)(__VA_ARGS__);})

#else // !TEST

#define MAGIC_CALLn(bswap_fptr, endian, nargs, func, ...)    \
    ({                                                                 \
        typeof((func)(__VA_ARGS__)) result;                            \
        asm volatile (                                                 \
            ASM_BODY_##endian(bswap_fptr, 1, nargs, func, __VA_ARGS__) \
            : [res]"=r"(result)                                        \
            : ASM_INPUTS(nargs, func, __VA_ARGS__)                     \
            : ASM_CLOBBERS                                             \
        );                                                             \
        result;                                                        \
    })

#endif // TEST

#define MAGIC_CALL_BE0(func)      MAGIC_CALLn(0, BE, 0, func)
#define MAGIC_CALL_BE1(func, ...) MAGIC_CALLn(0, BE, 1, func, __VA_ARGS__)
#define MAGIC_CALL_BE2(func, ...) MAGIC_CALLn(0, BE, 2, func, __VA_ARGS__)
#define MAGIC_CALL_BE3(func, ...) MAGIC_CALLn(0, BE, 3, func, __VA_ARGS__)
#define MAGIC_CALL_BE4(func, ...) MAGIC_CALLn(0, BE, 4, func, __VA_ARGS__)
#define MAGIC_CALL_BE5(func, ...) MAGIC_CALLn(0, BE, 5, func, __VA_ARGS__)
#define MAGIC_CALL_BE6(func, ...) MAGIC_CALLn(0, BE, 6, func, __VA_ARGS__)
#define MAGIC_CALL_BE7(func, ...) MAGIC_CALLn(0, BE, 7, func, __VA_ARGS__)

#define MAGIC_CALL_LE0(func)      MAGIC_CALLn(0, LE, 0, func)
#define MAGIC_CALL_LE1(func, ...) MAGIC_CALLn(0, LE, 1, func, __VA_ARGS__)
#define MAGIC_CALL_LE2(func, ...) MAGIC_CALLn(0, LE, 2, func, __VA_ARGS__)
#define MAGIC_CALL_LE3(func, ...) MAGIC_CALLn(0, LE, 3, func, __VA_ARGS__)
#define MAGIC_CALL_LE4(func, ...) MAGIC_CALLn(0, LE, 4, func, __VA_ARGS__)
#define MAGIC_CALL_LE5(func, ...) MAGIC_CALLn(0, LE, 5, func, __VA_ARGS__)
#define MAGIC_CALL_LE6(func, ...) MAGIC_CALLn(0, LE, 6, func, __VA_ARGS__)
#define MAGIC_CALL_LE7(func, ...) MAGIC_CALLn(0, LE, 7, func, __VA_ARGS__)
