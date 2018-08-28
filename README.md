# core2elf

Recovering ELF from memory dumps are not new and are well discussed many times in many places. I have used Silvio Cesare's work [ELF EXECUTABLE RECONSTRUCTION FROM A CORE IMAGE] and code here to rebuild many of ELF metadata along with dynamic linking details.

Many of these section headers may or may not exists. This is just POC code.

### SAMPLE ###

```
renorobert@ubuntu:~/corerec$ ./hello
Hello World!

renorobert@ubuntu:~/corerec$ file core
core: ELF 32-bit LSB  core file Intel 80386, version 1 (SYSV), SVR4-style, from '/home/renorobert/corerec/hello'

renorobert@ubuntu:~/corerec$ ./core_recover 
[*] Program headers of CORE
	0x00000000 - 0x00000000
	0x08048000 - 0x08049000
	0x08049000 - 0x0804a000
	0x0804a000 - 0x0804b000
	0xf7e09000 - 0xf7e0a000
	0xf7e0a000 - 0xf7fb2000
	0xf7fb2000 - 0xf7fb4000
	0xf7fb4000 - 0xf7fb5000
	0xf7fb5000 - 0xf7fb8000
	0xf7fd7000 - 0xf7fd9000
	0xf7fd9000 - 0xf7fda000
	0xf7fda000 - 0xf7fdc000
	0xf7fdc000 - 0xf7ffc000
	0xf7ffc000 - 0xf7ffd000
	0xf7ffd000 - 0xf7ffe000
	0xfffdc000 - 0xffffe000

[*] Program headers of ELF
	0x08048034 - 0x08048154
	0x08048154 - 0x08048167
	0x08048000 - 0x080485bc
	0x08049f08 - 0x0804a024
	0x08049f14 - 0x08049ffc
	0x08048168 - 0x080481ac
	0x080484e0 - 0x0804850c
	0x00000000 - 0x00000000
	0x08049f08 - 0x0804a000

[*] Building section headers from program headers
[*] Building section headers from DYNAMIC section
[*] 6 GOT entries found
[*] Patching GOT entries to PLT address
[*] Done

renorobert@ubuntu:~/corerec$ file ./rebuild.elf 
./rebuild.elf: ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, stripped


renorobert@ubuntu:~/corerec$ readelf -a ./rebuild.elf 
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Version:                           0x1
  Entry point address:               0x8048320
  Start of program headers:          52 (bytes into file)
  Start of section headers:          4412 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         9
  Size of section headers:           40 (bytes)
  Number of section headers:         25
  Section header string table index: 1

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .shstrtab         STRTAB          00000000 001020 00011c 00      0   0  1
  [ 2] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 3] .dynamic          DYNAMIC         08049f14 000f14 0000e8 08   A  0   0  4
  [ 4] .note             NOTE            08048168 000168 000044 00   A  0   0  1
  [ 5] .eh_frame_hdr     PROGBITS        080484e0 0004e0 00002c 00   A  0   0  4
  [ 6] .eh_frame         PROGBITS        0804850c 00050c 0000b0 00   A  0   0  4
  [ 7] .bss              NOBITS          0804a020 001020 000004 00  WA  0   0  4
  [ 8] .init_array       INIT_ARRAY      08049f08 000f08 000004 00  WA  0   0  4
  [ 9] .fini_array       FINI_ARRAY      08049f0c 000f0c 000004 00  WA  0   0  4
  [10] .jcr              PROGBITS        08049f10 000f10 000004 00  WA  0   0  4
  [11] .got.plt          PROGBITS        0804a000 001000 000018 00  WA  0   0  4
  [12] .data             PROGBITS        0804a018 001018 000008 00  WA  0   0  4
  [13] .dynstr           STRTAB          0804821c 00021c 000049 00   A  0   0  1
  [14] .dynsym           DYNSYM          080481cc 0001cc 000050 10   A 13   2  4
  [15] .init             PROGBITS        080482b0 0002b0 000030 00  AX  0   0  4
  [16] .plt              PROGBITS        080482e0 0002e0 000040 04  AX  0   0 16
  [17] .text             PROGBITS        08048320 000320 000194 00  AX  0   0 16
  [18] .fini             PROGBITS        080484b4 0004b4 000000 00  AX  0   0  4
  [19] .rel.dyn          REL             08048290 000290 000008 08   A 14   0  4
  [20] .rel.plt          REL             08048298 000298 000018 08   A 14  16  4
  [21] .gnu.version      VERSYM          08048266 000266 00000a 02   A 14   0  2
  [22] .gnu.version_r    VERNEED         08048270 000270 000020 00   A 13   1  4
  [23] .gnu.hash         GNU_HASH        080481ac 0001ac 000020 00   A 14   0  4
  [24] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings)
  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
  O (extra OS processing required) o (OS specific), p (processor specific)

There are no section groups in this file.

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00120 0x00120 R E 0x4
  INTERP         0x000154 0x08048154 0x08048154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x08048000 0x08048000 0x005bc 0x005bc R E 0x1000
  LOAD           0x000f08 0x08049f08 0x08049f08 0x00118 0x0011c RW  0x1000
  DYNAMIC        0x000f14 0x08049f14 0x08049f14 0x000e8 0x000e8 RW  0x4
  NOTE           0x000168 0x08048168 0x08048168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x0004e0 0x080484e0 0x080484e0 0x0002c 0x0002c R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
  GNU_RELRO      0x000f08 0x08049f08 0x08049f08 0x000f8 0x000f8 R   0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .interp .note .eh_frame_hdr .eh_frame .dynstr .dynsym .init .plt .text .fini .rel.dyn .rel.plt .gnu.version .gnu.version_r .gnu.hash 
   03     .dynamic .bss .init_array .fini_array .jcr .got.plt .data .got 
   04     .dynamic 
   05     .note 
   06     .eh_frame_hdr 
   07     
   08     .dynamic .init_array .fini_array .jcr .got 

Dynamic section at offset 0xf14 contains 24 entries:
  Tag        Type                         Name/Value
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000c (INIT)                       0x80482b0
 0x0000000d (FINI)                       0x80484b4
 0x00000019 (INIT_ARRAY)                 0x8049f08
 0x0000001b (INIT_ARRAYSZ)               4 (bytes)
 0x0000001a (FINI_ARRAY)                 0x8049f0c
 0x0000001c (FINI_ARRAYSZ)               4 (bytes)
 0x6ffffef5 (GNU_HASH)                   0x80481ac
 0x00000005 (STRTAB)                     0x804821c
 0x00000006 (SYMTAB)                     0x80481cc
 0x0000000a (STRSZ)                      74 (bytes)
 0x0000000b (SYMENT)                     16 (bytes)
 0x00000015 (DEBUG)                      0xf7ffd924
 0x00000003 (PLTGOT)                     0x804a000
 0x00000002 (PLTRELSZ)                   24 (bytes)
 0x00000014 (PLTREL)                     REL
 0x00000017 (JMPREL)                     0x8048298
 0x00000011 (REL)                        0x8048290
 0x00000012 (RELSZ)                      8 (bytes)
 0x00000013 (RELENT)                     8 (bytes)
 0x6ffffffe (VERNEED)                    0x8048270
 0x6fffffff (VERNEEDNUM)                 1
 0x6ffffff0 (VERSYM)                     0x8048266
 0x00000000 (NULL)                       0x0

Relocation section '.rel.dyn' at offset 0x290 contains 1 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
08049ffc  00000206 R_386_GLOB_DAT    00000000   __gmon_start__

Relocation section '.rel.plt' at offset 0x298 contains 3 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a00c  00000107 R_386_JUMP_SLOT   00000000   puts
0804a010  00000207 R_386_JUMP_SLOT   00000000   __gmon_start__
0804a014  00000307 R_386_JUMP_SLOT   00000000   __libc_start_main

The decoding of unwind sections for machine type Intel 80386 is not currently supported.

Symbol table '.dynsym' contains 5 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 00000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.0 (2)
     2: 00000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     3: 00000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.0 (2)
     4: 080484cc     4 OBJECT  GLOBAL DEFAULT   15 _IO_stdin_used

Histogram for `.gnu.hash' bucket list length (total of 2 buckets):
 Length  Number     % of total  Coverage
      0  1          ( 50.0%)
      1  1          ( 50.0%)    100.0%

Version symbols section '.gnu.version' contains 5 entries:
 Addr: 0000000008048266  Offset: 0x000266  Link: 14 (.dynsym)
  000:   0 (*local*)       2 (GLIBC_2.0)     0 (*local*)       2 (GLIBC_2.0)  
  004:   1 (*global*)   

Version needs section '.gnu.version_r' contains 1 entries:
 Addr: 0x0000000008048270  Offset: 0x000270  Link: 13 (.dynstr)
  000000: Version: 1  File: libc.so.6  Cnt: 1
  0x0010:   Name: GLIBC_2.0  Flags: none  Version: 2

Displaying notes found at file offset 0x00000168 with length 0x00000044:
  Owner                 Data size	Description
  GNU                  0x00000010	NT_GNU_ABI_TAG (ABI version tag)
    OS: Linux, ABI: 2.6.24
  GNU                  0x00000014	NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: e8ee1fa34adec405fcd55e166c0508d2f941b6f2

renorobert@ubuntu:~/corerec$ ./rebuild.elf 
Hello World!

renorobert@ubuntu:~/corerec$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 14.04.2 LTS
Release:	14.04
Codename:	trusty


renorobert@ubuntu:~/corerec$ uname -a
Linux ubuntu 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:43:14 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
```
