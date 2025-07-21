## Challenge Description
So, PDFs are Turing complete and can run Doom. In fact, [they can even run Linux](https://github.com/ading2210/linuxpdf).
I was thinking that we could make them check flags too.
The checker might freeze sometimes, but it's not a bug, it's a feature, otherwise how could you get it printed?

## Challenge Files
- `hardware-assisted.pdf`: the challenge, a PDF file

## Walkthrough
Note: the challenge was based on `linuxpdf`, specifically on the commit `9d6ff291a3c1f157b22ae6d196c9a3841a3de289`, which is the last commit at the time of writing. The challenge does not rely on a specific version of `linuxpdf`, and the RISC-V emulator it contains should not change between versions, but the patch we give may not apply cleanly to future or past versions. 

The challenge presents itself as a PDF file. When opened on a Chromium-based browser, it will run a RISC-V emulator that executes a real Linux kernel, which in turn runs an executable performing the flag checking operation.

I will now give a brief overview of the (sort of) intended solution.

The first thing we can observe, and the challenge description hints that this might happen too, is that, by trying random inputs, the checker will sometimes lockup, freezing the whole VM. In some other cases, it will simply return that the flag is incorrect. 

The first thing we need to do is to extract the JavaScript code from the PDF file. The `linuxpdf` repository linked in the description contains the generation script, so we can simply ask our favorite LLM to write a script based on it that extracts the JavaScript code from the PDF file. I will attach my version of the script in `extractor.py`.

The first script extracted, named `script_1.js`, contains all the files for the RISC-V emulated system, including the checker file that our PDF runs, encoded in base64.

Inside it, we find `embedded_files`, a large JavaScript dictionary which contains all the files of the VM's file system.
One of these files is our checker binary, and we can attempt to extract and decompress all of them until we find the checker binary (for example, by looking for one the messages printed by the checker, such as "you remember").
I will attach my version of the script `file_decoder.py`, which does exactly that.

We can now run `file` on the checker ELF, and confirm that it is indeed a RISC-V binary.
```bash
➜  chall file checker
checker: ELF 32-bit LSB executable, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV), statically linked, stripped
```

Opening it in IDA (or any other decompiler), will yield something like this:
```c
int sub_103E6()
{
  int v0; // a0
  int v1; // a0
  int v2; // a0
  int v4; // [sp+8h] [-28h]
  int n; // [sp+Ch] [-24h]
  int m; // [sp+10h] [-20h]
  int k; // [sp+14h] [-1Ch]
  int j; // [sp+18h] [-18h]
  int i; // [sp+1Ch] [-14h]

  ((void (*)(void))loc_101DE)();
  for ( i = 0; i <= 63; ++i )
    dword_135D4[i] = 0;
  sub_10A46("Welcome to PROVOLA-FS");
  sub_10A46("PDF-based Responsive Online Virtual Optimized Linux-running Assistant for Flag Storage");
  sub_10A46("Let's see if you remember the flag:");
  sub_1080A(off_13528);
  sub_108FC(byte_13594, 64, off_13524);
  byte_13594[sub_10FE0(byte_13594, "\n")] = 0;
  v4 = sub_11078(byte_13594);
  for ( j = 0; j < v4; ++j )
    ((void (__fastcall *)(_DWORD, _DWORD))loc_101B0)(dword_13000[j], byte_13594[j]);
  sub_10A46("It might be right, let's check it some more...");
  for ( k = 0; k <= 31; ++k )
  {
    v0 = sub_107C8();
    ((void (__fastcall *)(int))loc_102F6)(v0);
  }
  sub_103A6(1);
  for ( m = 0; m < v4; ++m )
  {
    v1 = ((int (__fastcall *)(_DWORD))loc_10250)(dword_13100[m]);
    v2 = ((int (__fastcall *)(int))loc_101F4)(v1);
    dword_135D4[m] = ((int (__fastcall *)(_DWORD, int))loc_10216)(byte_13594[v2], dword_13530);
  }
  sub_10A46("We're almost done, I swear...");
  sub_103A6(1);
  sub_1031C(77824, dword_135D4, &unk_13200);
  for ( n = 0; n <= 63; ++n )
    ((void (*)(void))loc_10390)();
  if ( ((int (__fastcall *)(int, void *))loc_10356)(77824, &unk_13300) )
    sub_10A46("That's the flag I remember, GG!");
  else
    sub_10A46("Nope. Have you tried the Konami code yet?");
  sub_103A6(1);
  return 0;
}
```
A single main function which seems to perform the entirety of the flag checking operation.

Something doesn't look right though: IDA sees a call to `loc_101DE`, which looks exactly like a function, but it cannot identify it as that.
Opening that function, we can see why:
```h
.text:000101DE loc_101DE:                              # CODE XREF: sub_103E6+8↓p
.text:000101DE # __unwind {
.text:000101DE                 addi            sp, sp, -10h
.text:000101E0                 sw              ra, 0Ch(sp)
.text:000101E2                 sw              s0, 8(sp)
.text:000101E4                 addi            s0, sp, 10h
.text:000101E4 # ---------------------------------------------------------------------------
.text:000101E6                 .half 0DBh
.text:000101E8                 .word dword_10000
.text:000101EC # ---------------------------------------------------------------------------
.text:000101EC                 lw              ra, 0Ch(sp)
.text:000101EE                 lw              s0, 8(sp)
.text:000101F0                 addi            sp, sp, 10h
.text:000101F2                 ret
.text:000101F2 # } // starts at 101DE
```

There are some instructions that IDA does not understand, and thus it cannot the sequence as a complete function.

The challenge name, `hardware-assisted`, hints at the fact that this might imply some sort of custom hardware instructions, which the executable relies on. Looking for the opcodes online, we can indeed confirm that they do not belong to the RISC-V ISA, and thus should cause the emulator to crash when executed.

Now, there are two sort-of-similar approaches we can take to proceed:
1. Given that the emulator is based on `linuxpdf`, we can take that, generate a new standard PDF file, extract the original JavaScript code and check for the differences between the two scripts. This should allows us to identify where the custom instructions have been added.
2. Alternatively, we can search for the new opcodes in the VM JavaScript code and directly try to understand what they do.

I personally thought that the first approach would be easier in the long run. When developing the challenge, I intentionally tried to keep the custom instructions simple, small, and close together. The JavaScript code was not minified, and I didn't change any build parameters, so other than some minor differences in variable names between the two scripts clobbering the diff, the custom instructions should be easily identifiable.

After running:
```bash
diff results/script_1.js linuxpdf/out/compiled.js
```
we can spot the following interesting difference between the two files:
```diff
8555c8793,9095
<      $$be1088 = $add$ptr2347;
---
>      $$be1233 = $add$ptr2347;
>      $cell_val1$0$be = $cell_val1$0;
>      $cell_val12516$0$be = $cell_val12516$0;
>      $cell_val2$0$be = $cell_val2$0;
>      $cell_val22517$0$be = $cell_val22517$0;
>      $funct3$0$be = $funct3$0;
>      break;
>     }
>    case 43:
>     {
>      if ($and133 | 0) {
>       $arrayidx2353 = 19816 + ($and133 << 2) | 0;
>       HEAP32[$arrayidx2353 >> 2] = 0;
>       $1231 = HEAP32[19816 + ($and135 << 2) >> 2] | 0;
>       if (($1231 | 0) != 1) {
>        $arrayidx2362 = 19816 + ($and137 << 2) | 0;
>        $1233 = 0;
>        $imm$01131 = $1231;
>        while (1) {
>         if (!($imm$01131 & 1)) $imm$1 = $imm$01131 >> 1; else $imm$1 = (Math_imul(HEAP32[$arrayidx2362 >> 2] | 0, $imm$01131) | 0) + 1 | 0;
>         $1233 = $1233 + 1 | 0;
>         HEAP32[$arrayidx2353 >> 2] = $1233;
>         if (($imm$1 | 0) == 1) break; else $imm$01131 = $imm$1;
>        }
>       }
>      }
>      $add$ptr2372 = (HEAP32[4986] | 0) + 4 | 0;
>      HEAP32[4986] = $add$ptr2372;
>      $$be = $add$ptr2372;
>      $$be1233 = $add$ptr2372;
>      $cell_val1$0$be = $cell_val1$0;
>      $cell_val12516$0$be = $cell_val12516$0;
>      $cell_val2$0$be = $cell_val2$0;
>      $cell_val22517$0$be = $cell_val22517$0;
>      $funct3$0$be = $funct3$0;
>      break;
>     }
>    case 11:
>     {
>      if (!$and133) {
>       if (($funct3$0 | 0) == 2) HEAP32[5065] = HEAP32[19816 + ($and135 << 2) >> 2];
>      } else HEAP32[19816 + ($and133 << 2) >> 2] = HEAP32[5063];
>      $add$ptr2388 = (HEAP32[4986] | 0) + 4 | 0;
>      HEAP32[4986] = $add$ptr2388;
>      $$be = $add$ptr2388;
>      $$be1233 = $add$ptr2388;
>      $cell_val1$0$be = $cell_val1$0;
>      $cell_val12516$0$be = $cell_val12516$0;
>      $cell_val2$0$be = $cell_val2$0;
>      $cell_val22517$0$be = $cell_val22517$0;
>      $funct3$0$be = $funct3$0;
>      break;
>     }
>    case 91:
>     {
>      HEAP32[5064] = 37;
>      HEAP32[5063] = 0;
>      $add$ptr2392 = (HEAP32[4986] | 0) + 4 | 0;
>      HEAP32[4986] = $add$ptr2392;
>      $$be = $add$ptr2392;
>      $$be1233 = $add$ptr2392;
>      $cell_val1$0$be = $cell_val1$0;
>      $cell_val12516$0$be = $cell_val12516$0;
>      $cell_val2$0$be = $cell_val2$0;
>      $cell_val22517$0$be = $cell_val22517$0;
>      $funct3$0$be = $funct3$0;
>      break;
>     }
>    case 107:
>     {
>      HEAP32[5063] = (HEAP32[5063] | 0) + 1;
>      $add$ptr2397 = (HEAP32[4986] | 0) + 4 | 0;
>      HEAP32[4986] = $add$ptr2397;
>      $$be = $add$ptr2397;
>      $$be1233 = $add$ptr2397;
>      $cell_val1$0$be = $cell_val1$0;
>      $cell_val12516$0$be = $cell_val12516$0;
>      $cell_val2$0$be = $cell_val2$0;
>      $cell_val22517$0$be = $cell_val22517$0;
>      $funct3$0$be = $funct3$0;
>      break;
>     }
>    case 123:
>     {
>      if ($and133 | 0) {
>       HEAP32[19816 + ($and133 << 2) >> 2] = HEAP32[5064];
>       HEAP32[5064] = (((HEAP32[5064] | 0) + 37 | 0) >>> 0) % 53 | 0;
>      }
>      $add$ptr2410 = (HEAP32[4986] | 0) + 4 | 0;
>      HEAP32[4986] = $add$ptr2410;
>      $$be = $add$ptr2410;
>      $$be1233 = $add$ptr2410;
>      $cell_val1$0$be = $cell_val1$0;
>      $cell_val12516$0$be = $cell_val12516$0;
>      $cell_val2$0$be = $cell_val2$0;
>      $cell_val22517$0$be = $cell_val22517$0;
>      $funct3$0$be = $funct3$0;
>      break;
>     }
>    case 63:
>     {
>      if ($and133 | 0) {
>       $arrayidx2416 = 19816 + ($and133 << 2) | 0;
>       HEAP32[$arrayidx2416 >> 2] = 1;
>       $arrayidx2419 = 19816 + ($and137 << 2) | 0;
>       $1249 = HEAP32[$arrayidx2419 >> 2] | 0;
>       if ($1249 | 0) {
>        $arrayidx2442 = 19816 + ($and135 << 2) | 0;
>        $1250 = $1249;
>        do {
>         if ($1250 & 1 | 0) {
>          $1253 = ___muldi3(HEAP32[$arrayidx2416 >> 2] | 0, 0, HEAP32[$arrayidx2442 >> 2] | 0, 0) | 0;
>          $1254 = getTempRet0() | 0;
>          $1256 = ___uremdi3($1253 | 0, $1254 | 0, HEAP32[5065] | 0, 0) | 0;
>          getTempRet0() | 0;
>          HEAP32[$arrayidx2416 >> 2] = $1256;
>         }
>         $1258 = HEAP32[$arrayidx2442 >> 2] | 0;
>         $1259 = ___muldi3($1258 | 0, 0, $1258 | 0, 0) | 0;
>         $1260 = getTempRet0() | 0;
>         $1262 = ___uremdi3($1259 | 0, $1260 | 0, HEAP32[5065] | 0, 0) | 0;
>         getTempRet0() | 0;
>         HEAP32[$arrayidx2442 >> 2] = $1262;
>         $1250 = (HEAP32[$arrayidx2419 >> 2] | 0) >>> 1;
>         HEAP32[$arrayidx2419 >> 2] = $1250;
>        } while (($1250 | 0) != 0);
>       }
>      }
>      $add$ptr2460 = (HEAP32[4986] | 0) + 4 | 0;
>      HEAP32[4986] = $add$ptr2460;
>      $$be = $add$ptr2460;
>      $$be1233 = $add$ptr2460;
>      $cell_val1$0$be = $cell_val1$0;
>      $cell_val12516$0$be = $cell_val12516$0;
>      $cell_val2$0$be = $cell_val2$0;
>      $cell_val22517$0$be = $cell_val22517$0;
>      $funct3$0$be = $funct3$0;
>      break;
>     }
>    case 87:
>     {
>      $1267 = HEAP32[19816 + ($and135 << 2) >> 2] | 0;
>      $1268 = HEAP32[19816 + ($and137 << 2) >> 2] | 0;
>      $1269 = HEAP32[19816 + ($and133 << 2) >> 2] | 0;
>      if (!$and133) {
>       $cell_val1$5 = $cell_val1$0;
>       $cell_val2$5 = $cell_val2$0;
>      } else {
>       $shr2471 = $insn$3 >>> 25;
>       if (!$shr2471) {
>        $cell_val1$5 = $cell_val1$0;
>        $cell_val2$5 = $cell_val2$0;
>       } else {
>        $cell_val1$11124 = $cell_val1$0;
>        $cell_val2$11125 = $cell_val2$0;
>        $i$01126 = 0;
>        while (1) {
>         $mul2485 = Math_imul($i$01126, $shr2471) | 0;
>         $cell_val1$21117 = $cell_val1$11124;
>         $cell_val2$21118 = $cell_val2$11125;
>         $j$01119 = 0;
>         while (1) {
>          $cell_val1$31108 = $cell_val1$21117;
>          $cell_val2$31109 = $cell_val2$21118;
>          $cell_val3$01110 = 0;
>          $k$01111 = 0;
>          while (1) {
>           $add2488 = ($k$01111 + $mul2485 << 2) + $1267 | 0;
>           $and$i151 = $add2488 >>> 12 & 255;
>           do if ((HEAP32[20352 + ($and$i151 << 3) >> 2] | 0) == ($add2488 & -4093 | 0)) $cell_val1$4 = HEAP32[(HEAP32[20352 + ($and$i151 << 3) + 4 >> 2] | 0) + $add2488 >> 2] | 0; else if (!(_riscv32_read_slow(19808, $val$i817, $add2488, 2) | 0)) {
>            $cell_val1$4 = HEAP32[$val$i817 >> 2] | 0;
>            break;
>           } else {
>            $cell_val1$4 = $cell_val1$31108;
>            break;
>           } while (0);
>           $add2493 = ((Math_imul($k$01111, $shr2471) | 0) + $j$01119 << 2) + $1268 | 0;
>           $and$i132 = $add2493 >>> 12 & 255;
>           do if ((HEAP32[20352 + ($and$i132 << 3) >> 2] | 0) == ($add2493 & -4093 | 0)) $cell_val2$4 = HEAP32[(HEAP32[20352 + ($and$i132 << 3) + 4 >> 2] | 0) + $add2493 >> 2] | 0; else if (!(_riscv32_read_slow(19808, $val$i817, $add2493, 2) | 0)) {
>            $cell_val2$4 = HEAP32[$val$i817 >> 2] | 0;
>            break;
>           } else {
>            $cell_val2$4 = $cell_val2$31109;
>            break;
>           } while (0);
>           $cell_val3$01110 = (Math_imul($cell_val2$4, $cell_val1$4) | 0) + $cell_val3$01110 | 0;
>           $k$01111 = $k$01111 + 1 | 0;
>           if (($k$01111 | 0) == ($shr2471 | 0)) break; else {
>            $cell_val1$31108 = $cell_val1$4;
>            $cell_val2$31109 = $cell_val2$4;
>           }
>          }
>          $add2502 = ($j$01119 + $mul2485 << 2) + $1269 | 0;
>          $and$i169 = $add2502 >>> 12 & 255;
>          if ((HEAP32[22400 + ($and$i169 << 3) >> 2] | 0) == ($add2502 & -4093 | 0)) HEAP32[(HEAP32[22400 + ($and$i169 << 3) + 4 >> 2] | 0) + $add2502 >> 2] = $cell_val3$01110; else _riscv32_write_slow(19808, $add2502, $cell_val3$01110, 0, 2) | 0;
>          $j$01119 = $j$01119 + 1 | 0;
>          if (($j$01119 | 0) == ($shr2471 | 0)) break; else {
>           $cell_val1$21117 = $cell_val1$4;
>           $cell_val2$21118 = $cell_val2$4;
>          }
>         }
>         $i$01126 = $i$01126 + 1 | 0;
>         if (($i$01126 | 0) == ($shr2471 | 0)) {
>          $cell_val1$5 = $cell_val1$4;
>          $cell_val2$5 = $cell_val2$4;
>          break;
>         } else {
>          $cell_val1$11124 = $cell_val1$4;
>          $cell_val2$11125 = $cell_val2$4;
>         }
>        }
>       }
>      }
>      $add$ptr2514 = (HEAP32[4986] | 0) + 4 | 0;
>      HEAP32[4986] = $add$ptr2514;
>      $$be = $add$ptr2514;
>      $$be1233 = $add$ptr2514;
>      $cell_val1$0$be = $cell_val1$5;
>      $cell_val12516$0$be = $cell_val12516$0;
>      $cell_val2$0$be = $cell_val2$5;
>      $cell_val22517$0$be = $cell_val22517$0;
>      $funct3$0$be = $funct3$0;
>      break;
>     }
>    case 127:
>     {
>      $1295 = HEAP32[19816 + ($and135 << 2) >> 2] | 0;
>      $1296 = HEAP32[19816 + ($and137 << 2) >> 2] | 0;
>      if (!$and133) {
>       $cell_val12516$6 = $cell_val12516$0;
>       $cell_val22517$6 = $cell_val22517$0;
>      } else {
>       $shr2527 = $insn$3 >>> 25;
>       L613 : do if (!$shr2527) {
>        $$sink = 1;
>        $cell_val12516$6$ph = $cell_val12516$0;
>        $cell_val22517$6$ph = $cell_val22517$0;
>       } else {
>        $cell_val12516$11102 = $cell_val12516$0;
>        $cell_val22517$11103 = $cell_val22517$0;
>        $i2528$01104 = 0;
>        while (1) {
>         $mul2540 = Math_imul($i2528$01104, $shr2527) | 0;
>         $cell_val12516$21097 = $cell_val12516$11102;
>         $cell_val22517$21098 = $cell_val22517$11103;
>         $j2534$01099 = 0;
>         while (1) {
>          $mul2542 = $j2534$01099 + $mul2540 << 2;
>          $add2543 = $mul2542 + $1295 | 0;
>          $and$i113 = $add2543 >>> 12 & 255;
>          do if ((HEAP32[20352 + ($and$i113 << 3) >> 2] | 0) == ($add2543 & -4093 | 0)) $cell_val12516$3 = HEAP32[(HEAP32[20352 + ($and$i113 << 3) + 4 >> 2] | 0) + $add2543 >> 2] | 0; else if (!(_riscv32_read_slow(19808, $val$i817, $add2543, 2) | 0)) {
>           $cell_val12516$3 = HEAP32[$val$i817 >> 2] | 0;
>           break;
>          } else {
>           $cell_val12516$3 = $cell_val12516$21097;
>           break;
>          } while (0);
>          $add2548 = $mul2542 + $1296 | 0;
>          $and$i98 = $add2548 >>> 12 & 255;
>          do if ((HEAP32[20352 + ($and$i98 << 3) >> 2] | 0) == ($add2548 & -4093 | 0)) $cell_val22517$3 = HEAP32[(HEAP32[20352 + ($and$i98 << 3) + 4 >> 2] | 0) + $add2548 >> 2] | 0; else if (!(_riscv32_read_slow(19808, $val$i817, $add2548, 2) | 0)) {
>           $cell_val22517$3 = HEAP32[$val$i817 >> 2] | 0;
>           break;
>          } else {
>           $cell_val22517$3 = $cell_val22517$21098;
>           break;
>          } while (0);
>          $j2534$01099 = $j2534$01099 + 1 | 0;
>          if (($cell_val12516$3 | 0) != ($cell_val22517$3 | 0)) {
>           $$sink = 0;
>           $cell_val12516$6$ph = $cell_val12516$3;
>           $cell_val22517$6$ph = $cell_val22517$3;
>           break L613;
>          }
>          if ($j2534$01099 >>> 0 >= $shr2527 >>> 0) break; else {
>           $cell_val12516$21097 = $cell_val12516$3;
>           $cell_val22517$21098 = $cell_val12516$3;
>          }
>         }
>         $i2528$01104 = $i2528$01104 + 1 | 0;
>         if ($i2528$01104 >>> 0 >= $shr2527 >>> 0) {
>          $$sink = 1;
>          $cell_val12516$6$ph = $cell_val12516$3;
>          $cell_val22517$6$ph = $cell_val12516$3;
>          break;
>         } else {
>          $cell_val12516$11102 = $cell_val12516$3;
>          $cell_val22517$11103 = $cell_val12516$3;
>         }
>        }
>       } while (0);
>       HEAP32[19816 + ($and133 << 2) >> 2] = $$sink;
>       $cell_val12516$6 = $cell_val12516$6$ph;
>       $cell_val22517$6 = $cell_val22517$6$ph;
>      }
>      $add$ptr2576 = (HEAP32[4986] | 0) + 4 | 0;
>      HEAP32[4986] = $add$ptr2576;
>      $$be = $add$ptr2576;
>      $$be1233 = $add$ptr2576;
>      $cell_val1$0$be = $cell_val1$0;
>      $cell_val12516$0$be = $cell_val12516$6;
>      $cell_val2$0$be = $cell_val2$0;
>      $cell_val22517$0$be = $cell_val22517$6;
>      $funct3$0$be = $funct3$0;
```
This is the biggest difference between the two scripts in terms of lines added or removed. The challenge has now become a JavaScript/hardware reverse engineering challenge, where the intention is to understand what the custom instructions do.

A good way to understand what the custom instructions do is to look at the other valid RISC-V instructions in the script. They can provide useful context in terms of ISA-specific operations, such as checking flags, opcode decoding, and so on.
The original TinyEMU RISC-V code is available too, and the compilation to JavaScript doesn't really change much of the code structure, so it can be used as a good reference.
Even with no other context, ChatGPT or Gemini Pro are able to help a lot in this process: https://g.co/gemini/share/98e86a14c43e.

Cleaning up the added JavaScript code a bit, we can reach the following pseudo-code:
```
uint32 gpr1, gpr2, gpr3;

[...]

case 91: // INIT_GPRS
    gpr2 = 37;
    gpr1 = 0;
    break;

case 107: // INC_GPR1
    gpr1 += 1;
    break;

case 123: // RAND
    if (rd) {
      Regs[rd] = gpr2;
      gpr2 = (gpr2 + 37) % 53;
    }
    break;

case 11: // MOV_GPR
    if (!rd) {
      if (funct3 == 2) gpr3 = Regs[rs1];
    } else {
      Regs[rd] = gpr1;
    }
    break;

case 43: // COLLATZ
    if (rd) {
      Regs[rd] = 0;
      int n = Regs[rs1];
      int m = Regs[rs2];
      while (n != 1) {
        if (n % 2 == 0) {
          n /= 2;
        } else {
          n = (m * n) + 1;
        }
        Regs[rd]++;
      }
    }
    break;

case 63: // MODEXP
    if (rd) {
      Regs[rd] = 1;
      int base = Regs[rs1];
      int exp = Regs[rs2];
      while (exp > 0) {
        if (exp % 2 == 1) {
          Regs[rd] = (Regs[rd] * base) % gpr3;
        }
        base = (base * base) % gpr3;
        exp /= 2;
      }
    }
    break;

case 87: // MATMUL
    // Matrix multiplication C = A * B
    // rd = address of matrix C, rs1 = address of matrix A, rs2 = address of matrix B, imm = dimension N
    Mat(Regs[rd]) = Mat(Regs[rs1]) * Mat(Regs[rs2]);
    break;

case 127: // MATCMP
    // Matrix comparison for equality
    // rd = destination, rs1 = address of matrix A, rs2 = address of matrix B, imm = dimension N
    if (Mat(Regs[rs1]) == Mat(Regs[rs2])) {
      Regs[rd] = 1;
    } else {
      Regs[rd] = 0;
    }
    break;
```

With our reversed instructions, we can now try to understand what the flag checking operation does.
The challenge initializes an integer array of 64 elements, which we could deduce to be an 8x8 matrix.
It then performs a few operations on the input to remove the trailing newline, then runs an operation on each of the characters, using the `COLLATZ` instruction. Each character must provide a stopping sequence for it. This check does not necessary provide much information about the flag, but we might be able to use it later to ensure that our reversed flag is correct.

After that, it calls opcode 11 a few times. This seems to be a no-op, and we can valide this assertion by dynamically debugging the VM and adding a few print statements to the JavaScript code.

It then does an operation on the user input by calling, for each character, opcode 11 again, and then opcodes 123 and 63:
```c
for ( m = 0; m < v18; ++m )
{
  v13 = ((int (__fastcall *)(_DWORD))opcode_11)(primes_list[m]);
  v14 = ((int (__fastcall *)(int))opcode_123)(v13);
  dword_135D4[m] = ((int (__fastcall *)(_DWORD, int))opcode_63)(user_input[v14], dword_13530);
}
```
What this is doing is the following:
1. For each character in the user input, it calls opcode 11 with the prime number. Opcode 11 has a specific condition for actually loading the prime number into `gpr3`: funct3 must be 2. If we decode the instruction, we can see that this is not the case, so the call is effectively a no-op. Dynamic analysis would be able to confirm this.
2. It then calls opcode 123, which will store the value of `gpr2` into the `gpr1`, and then increment `gpr2` by 37. This is a pseudo-random number generator, with a set seed, shuffling the flag characters.
3. Finally, it calls opcode 63, which performs a modular exponentiation operation on the character, a set exponent, and the prime in `gpr3`. 

Given that we never set `gpr3`, we need to identify its real value. The quickest way to do this is to run the VM, have the encryption operation be performed, and dump the value of the `gpr3` register at runtime. This will give a value of `gpr3 = 132305471`, which is our result.
Alternatively, one could bruteforce the following operations on all the primes found in the checker, or statically analyze the rest of the checker code to identify where the value of `gpr3` is really set.

After that, the executable performs a final operation on the shuffled and encrypted input flag: it multiplies it with another matrix of size 8x8 embedded in the executable, and then checks if the result matches a hardcoded matrix. This is done by calling opcode 87, which performs a matrix multiplication, and then opcode 127, which checks if two matrices are equal.

Therefore, we can simply reverse the matrix multiplication operation:
```py
import numpy as np
import galois
from Crypto.Util.number import getPrime

p = 132305471
hardcoded_matrix = [2, 4, 5, 2, 5, 6, 3, 6, 0, 1, 6, 1, 1, 3, 0, 6, 0, 2, 7, 3, 3, 0, 6, 7, 4, 4, 4, 7, 7, 2, 4, 2, 7, 2, 0, 1, 0, 5, 6, 6, 7, 2, 7, 6, 3, 7, 0, 5, 2, 7, 1, 0, 0, 7, 0, 7, 3, 2, 7, 4, 2, 5, 3, 5]
final_result = [1484638270, 1358394557, 2448420672, 1888027793, 1554595538, 1770248929, 1061849419, 2327371760, 1674584143, 2214251129, 3401630290, 2140773114, 2009586345, 2765381674, 1563966910, 3729119976, 1077118114, 994584661, 2107154298, 1146273244, 905570288, 1777048165, 623138246, 2175895842, 1289583394, 992594887, 1950489443, 1018596198, 745566417, 1667470939, 1450844439, 2577492348, 2318166469, 1828155266, 2732147902, 1713352019, 1392216269, 3237106805, 1394529459, 3524444224, 1522857892, 829162340, 1989865120, 1293113777, 753002171, 1870770854, 924159150, 2010158908, 818923168, 838619788, 1576950389, 1139838011, 1154701229, 920966690, 1086674068, 1649764659, 0, 0, 0, 0, 0, 0, 0, 0]

GF = galois.GF(getPrime(33))
hardcoded_matrix = [hardcoded_matrix[i:i + 8] for i in range(0, len(hardcoded_matrix), 8)]
final_result = [final_result[i:i + 8] for i in range(0, len(final_result), 8)]
hardcoded_matrix = GF(hardcoded_matrix)
final_result = GF(final_result)

inv_second_check = np.linalg.inv(hardcoded_matrix)
orig = np.matmul(final_result, inv_second_check)
print(orig)
```

From the given matrix, we can then decrypt and unshuffle the characters to reveal the flag:
```py
flag_enc = orig.flatten()

e = 8971
d = pow(e, -1, p - 1)

flag = ""

for x in flag_enc:
    try:
        flag += chr(pow(int(x), d, p))
    except:
        flag += "?"

# unshuffle
new_flag = ['_'] * 64
base = 37
for i in range(53):
    new_flag[base] = flag[i]
    base = (base + 37) % 53

print("".join(new_flag))
```

This will give us the final flag:
```
toh{n3xt_t1m3_w3_4r3_runn1ng_w1nd0ws_0n_th1s_b4d_b0y}
```