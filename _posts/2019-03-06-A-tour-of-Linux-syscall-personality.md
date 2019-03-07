---
title: A tour of Linux syscall personality
tags: ['CTF', 'PWN']
---

## 概述

系统调用`personality`是Linux平台上特定的系统调用，中文文档当前较少，本文将围绕这个系统调用做一些简单翻译与使用示例

> DESCRIPTION
> 
> Linux  supports  different execution domains, or personalities, for each process.  Among
> other things, execution domains tell  Linux  how  to  map  signal  numbers  into  signal
> actions.   The execution domain system allows Linux to provide limited support for bina‐
> ries compiled under other UNIX-like operating systems.

Linux支持对不同的进程有着不同的执行域（或者个性），执行域允许Linux为在其他类UNIX操作系统下编译好的二进制文件提供有限的支持。另外，执行域能够指引系统如何将信号映射到具体响应动作

而`personality`就是设置这个执行域的相关系统调用，在x86-64架构下的系统调用方式如下：

| %rax | %rdi | Name | Implementation |
| ---- | ---- | ---- | -------------- |
| 135  | unsigned int persona | personality | [kernel/exec_domain.c](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/kernel/exec_domain.c) |


在`glibc`中封装的头文件与函数定义如下：

```c
#include <sys/personality.h>

int personality(unsigned long persona);

```

其中当参数`persona != 0xffffffff`时，该函数会将调用者的执行域设置为`persona`的值，而当`persona`的值为`0xffffffff`时，则不改变执行域，并返回调用者当前执行域的值

可用的执行域列表可以在头文件`<sys/personality.h>`中找到，在x86-64架构的Linux系统中文件位置通常在`/usr/include/x86_64-linux-gnu/sys/personality.h`

执行域是一个32位长度的值，其中最高的三字节被预留出来用于标记，这些标记会导致内核修改某些系统调用的行为，以便进行模拟一些历史问题或架构问题。
同时最低的一个有效字节，定义了内核应该具有的个性

参数persona列表（部分）

| 名称 | 描述 |
| ---- | ---- |
| ADDR_NO_RANDOMIZE | (since Linux 2.6.12) 关闭ASLR |
| READ_IMPLIES_EXEC | (since Linux 2.6.8) 在调用mmap时，使用PROT_READ就意味着使用PROT_EXEC |
| - | [read more](http://man7.org/linux/man-pages/man2/personality.2.html#DESCRIPTION) |

当函数执行成功时，会将上一个`persona`作为返回值，而失败时，则返回-1，并且会设置errno。

## 代码示例

### READ_IMPLIES_EXEC

```c
// gcc -g -fPIE -pie -fstack-protector-all \
	-Wl,-z,relro,-z,now -o read_implies_exec ./read_implies_exec.c
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/personality.h>

#define DEFAULT_MAPS_SIZE 1024<<1

#define die(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

void dump_maps()
{
	puts("\n >>>>>>>>>>>>>>>>>>>> MAPS <<<<<<<<<<<<<<<<<<<<\n");
	int fd = open("/proc/self/maps", O_RDONLY);
	char* buf = calloc(DEFAULT_MAPS_SIZE, 1);
	int rn = read(fd, buf, DEFAULT_MAPS_SIZE);
	write(1, buf, rn);
	memset(buf, 0, DEFAULT_MAPS_SIZE);
	free(buf);
	close(fd);
	puts("\n ==================== END ====================\n");
}

void * mmap_rw_page(int size)
{
	void *ret = mmap(0, size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, 0, 0);
	if (ret == MAP_FAILED) 
		die("mmap() error");
}

int main()
{
	dump_maps();
	/* mmap a Read/Write page */
	void *ro_page = mmap_rw_page(0x1000);
	printf("mmap(rw-) : %p\n", ro_page);
	dump_maps();

	/* change process personality */
	if (personality(READ_IMPLIES_EXEC) == -1) 
		die("personality() error");
	/* 
	   do the same mmap, only to find out
	   that the protection is diffrent.
	*/
	void *rwx_page = mmap_rw_page(0x1000);
	printf("mmap(rwx) : %p\n", rwx_page);
	dump_maps();

	/* Cleanup */
	munmap(ro_page, 0x1000);
	munmap(rwx_page, 0x1000);
	return 0;
}
```

编译并运行程序得到的输出结果：
```text
 >>>>>>>>>>>>>>>>>>>> MAPS <<<<<<<<<<<<<<<<<<<<

556cb00f5000-556cb00f6000 r-xp 00000000 00:2a 72072                      /tmp/SYS_personality/read_implies_exec
556cb02f6000-556cb02f7000 r--p 00001000 00:2a 72072                      /tmp/SYS_personality/read_implies_exec
556cb02f7000-556cb02f8000 rw-p 00002000 00:2a 72072                      /tmp/SYS_personality/read_implies_exec
556cb07bb000-556cb07dc000 rw-p 00000000 00:00 0                          [heap]
7efd0b22f000-7efd0b3ef000 r-xp 00000000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7efd0b3ef000-7efd0b5ef000 ---p 001c0000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7efd0b5ef000-7efd0b5f3000 r--p 001c0000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7efd0b5f3000-7efd0b5f5000 rw-p 001c4000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7efd0b5f5000-7efd0b5f9000 rw-p 00000000 00:00 0 
7efd0b5f9000-7efd0b61f000 r-xp 00000000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7efd0b803000-7efd0b806000 rw-p 00000000 00:00 0 
7efd0b81e000-7efd0b81f000 r--p 00025000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7efd0b81f000-7efd0b820000 rw-p 00026000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7efd0b820000-7efd0b821000 rw-p 00000000 00:00 0 
7ffd2028e000-7ffd202af000 rw-p 00000000 00:00 0                          [stack]
7ffd2031b000-7ffd2031e000 r--p 00000000 00:00 0                          [vvar]
7ffd2031e000-7ffd20320000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

 ==================== END ====================

mmap(rw-) : 0x7efd0b81d000

 >>>>>>>>>>>>>>>>>>>> MAPS <<<<<<<<<<<<<<<<<<<<

556cb00f5000-556cb00f6000 r-xp 00000000 00:2a 72072                      /tmp/SYS_personality/read_implies_exec
556cb02f6000-556cb02f7000 r--p 00001000 00:2a 72072                      /tmp/SYS_personality/read_implies_exec
556cb02f7000-556cb02f8000 rw-p 00002000 00:2a 72072                      /tmp/SYS_personality/read_implies_exec
556cb07bb000-556cb07dc000 rw-p 00000000 00:00 0                          [heap]
7efd0b22f000-7efd0b3ef000 r-xp 00000000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7efd0b3ef000-7efd0b5ef000 ---p 001c0000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7efd0b5ef000-7efd0b5f3000 r--p 001c0000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7efd0b5f3000-7efd0b5f5000 rw-p 001c4000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7efd0b5f5000-7efd0b5f9000 rw-p 00000000 00:00 0 
7efd0b5f9000-7efd0b61f000 r-xp 00000000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7efd0b803000-7efd0b806000 rw-p 00000000 00:00 0 
7efd0b81d000-7efd0b81e000 rw-p 00000000 00:00 0 
7efd0b81e000-7efd0b81f000 r--p 00025000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7efd0b81f000-7efd0b820000 rw-p 00026000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7efd0b820000-7efd0b821000 rw-p 00000000 00:00 0 
7ffd2028e000-7ffd202af000 rw-p 00000000 00:00 0                          [stack]
7ffd2031b000-7ffd2031e000 r--p 00000000 00:00 0                          [vvar]
7ffd2031e000-7ffd20320000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

 ==================== END ====================

mmap(rwx) : 0x7efd0b81c000

 >>>>>>>>>>>>>>>>>>>> MAPS <<<<<<<<<<<<<<<<<<<<

556cb00f5000-556cb00f6000 r-xp 00000000 00:2a 72072                      /tmp/SYS_personality/read_implies_exec
556cb02f6000-556cb02f7000 r--p 00001000 00:2a 72072                      /tmp/SYS_personality/read_implies_exec
556cb02f7000-556cb02f8000 rw-p 00002000 00:2a 72072                      /tmp/SYS_personality/read_implies_exec
556cb07bb000-556cb07dc000 rw-p 00000000 00:00 0                          [heap]
7efd0b22f000-7efd0b3ef000 r-xp 00000000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7efd0b3ef000-7efd0b5ef000 ---p 001c0000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7efd0b5ef000-7efd0b5f3000 r--p 001c0000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7efd0b5f3000-7efd0b5f5000 rw-p 001c4000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7efd0b5f5000-7efd0b5f9000 rw-p 00000000 00:00 0 
7efd0b5f9000-7efd0b61f000 r-xp 00000000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7efd0b803000-7efd0b806000 rw-p 00000000 00:00 0 
7efd0b81c000-7efd0b81d000 rwxp 00000000 00:00 0 
7efd0b81d000-7efd0b81e000 rw-p 00000000 00:00 0 
7efd0b81e000-7efd0b81f000 r--p 00025000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7efd0b81f000-7efd0b820000 rw-p 00026000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7efd0b820000-7efd0b821000 rw-p 00000000 00:00 0 
7ffd2028e000-7ffd202af000 rw-p 00000000 00:00 0                          [stack]
7ffd2031b000-7ffd2031e000 r--p 00000000 00:00 0                          [vvar]
7ffd2031e000-7ffd20320000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

 ==================== END ====================

```

**分析**：

从输出可以看出当第一次`mmap`时，获得的内存块`0x7efd0b81d000`的保护属性为**`rw-`**，
而当调用`personality(READ_IMPLIES_EXEC)`后，再一次mmap得到的内存块`0x7efd0b81c000`的保护属性则为**`rwx`**，
虽然这两次mmap所提供的参数是一样的，但是由于personality的影响，导致其保护属性出现了不一致。

### ADDR_NO_RANDOMIZE

```c
// gcc -g -fPIE -pie -fstack-protector-all \
	-Wl,-z,relro,-z,now -o addr_no_randomize ./addr_no_randomize.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/personality.h>

#define die(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

void run_cat_self_maps()
{
	puts("\n >>>>>>>>>>>>>>>>>>>> MAPS <<<<<<<<<<<<<<<<<<<<\n");
	system("cat /proc/self/maps");
	puts("\n ==================== END ====================\n");	
}

int main()
{
	run_cat_self_maps();
	run_cat_self_maps();

	/* change process personality */
	if (personality(ADDR_NO_RANDOMIZE) == -1) 
		die("personality() error");

	run_cat_self_maps();
	run_cat_self_maps();

	return 0;
}

```

编译并运行程序得到的输出结果：
```text
 >>>>>>>>>>>>>>>>>>>> MAPS <<<<<<<<<<<<<<<<<<<<

00400000-0040c000 r-xp 00000000 08:01 664893                             /bin/cat
0060b000-0060c000 r--p 0000b000 08:01 664893                             /bin/cat
0060c000-0060d000 rw-p 0000c000 08:01 664893                             /bin/cat
00bbb000-00bdc000 rw-p 00000000 00:00 0                                  [heap]
7fc931ed2000-7fc9321aa000 r--p 00000000 08:01 788167                     /usr/lib/locale/locale-archive
7fc9321aa000-7fc93236a000 r-xp 00000000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7fc93236a000-7fc93256a000 ---p 001c0000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7fc93256a000-7fc93256e000 r--p 001c0000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7fc93256e000-7fc932570000 rw-p 001c4000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7fc932570000-7fc932574000 rw-p 00000000 00:00 0 
7fc932574000-7fc93259a000 r-xp 00000000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7fc93275c000-7fc932781000 rw-p 00000000 00:00 0 
7fc932799000-7fc93279a000 r--p 00025000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7fc93279a000-7fc93279b000 rw-p 00026000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7fc93279b000-7fc93279c000 rw-p 00000000 00:00 0 
7ffd7dd84000-7ffd7dda5000 rw-p 00000000 00:00 0                          [stack]
7ffd7ddfb000-7ffd7ddfe000 r--p 00000000 00:00 0                          [vvar]
7ffd7ddfe000-7ffd7de00000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

 ==================== END ====================


 >>>>>>>>>>>>>>>>>>>> MAPS <<<<<<<<<<<<<<<<<<<<

00400000-0040c000 r-xp 00000000 08:01 664893                             /bin/cat
0060b000-0060c000 r--p 0000b000 08:01 664893                             /bin/cat
0060c000-0060d000 rw-p 0000c000 08:01 664893                             /bin/cat
00d73000-00d94000 rw-p 00000000 00:00 0                                  [heap]
7f0dbca38000-7f0dbcd10000 r--p 00000000 08:01 788167                     /usr/lib/locale/locale-archive
7f0dbcd10000-7f0dbced0000 r-xp 00000000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7f0dbced0000-7f0dbd0d0000 ---p 001c0000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7f0dbd0d0000-7f0dbd0d4000 r--p 001c0000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7f0dbd0d4000-7f0dbd0d6000 rw-p 001c4000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7f0dbd0d6000-7f0dbd0da000 rw-p 00000000 00:00 0 
7f0dbd0da000-7f0dbd100000 r-xp 00000000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7f0dbd2c2000-7f0dbd2e7000 rw-p 00000000 00:00 0 
7f0dbd2ff000-7f0dbd300000 r--p 00025000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7f0dbd300000-7f0dbd301000 rw-p 00026000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7f0dbd301000-7f0dbd302000 rw-p 00000000 00:00 0 
7ffe8b933000-7ffe8b954000 rw-p 00000000 00:00 0                          [stack]
7ffe8b9c9000-7ffe8b9cc000 r--p 00000000 00:00 0                          [vvar]
7ffe8b9cc000-7ffe8b9ce000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

 ==================== END ====================


 >>>>>>>>>>>>>>>>>>>> MAPS <<<<<<<<<<<<<<<<<<<<

00400000-0040c000 r-xp 00000000 08:01 664893                             /bin/cat
0060b000-0060c000 r--p 0000b000 08:01 664893                             /bin/cat
0060c000-0060d000 rw-p 0000c000 08:01 664893                             /bin/cat
0060d000-0062e000 rw-p 00000000 00:00 0                                  [heap]
7ffff7735000-7ffff7a0d000 r--p 00000000 08:01 788167                     /usr/lib/locale/locale-archive
7ffff7a0d000-7ffff7bcd000 r-xp 00000000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7bcd000-7ffff7dcd000 ---p 001c0000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dcd000-7ffff7dd1000 r--p 001c0000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dd1000-7ffff7dd3000 rw-p 001c4000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dd3000-7ffff7dd7000 rw-p 00000000 00:00 0 
7ffff7dd7000-7ffff7dfd000 r-xp 00000000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7fba000-7ffff7fdf000 rw-p 00000000 00:00 0 
7ffff7ff7000-7ffff7ffa000 r--p 00000000 00:00 0                          [vvar]
7ffff7ffa000-7ffff7ffc000 r-xp 00000000 00:00 0                          [vdso]
7ffff7ffc000-7ffff7ffd000 r--p 00025000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7ffd000-7ffff7ffe000 rw-p 00026000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0 
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

 ==================== END ====================


 >>>>>>>>>>>>>>>>>>>> MAPS <<<<<<<<<<<<<<<<<<<<

00400000-0040c000 r-xp 00000000 08:01 664893                             /bin/cat
0060b000-0060c000 r--p 0000b000 08:01 664893                             /bin/cat
0060c000-0060d000 rw-p 0000c000 08:01 664893                             /bin/cat
0060d000-0062e000 rw-p 00000000 00:00 0                                  [heap]
7ffff7735000-7ffff7a0d000 r--p 00000000 08:01 788167                     /usr/lib/locale/locale-archive
7ffff7a0d000-7ffff7bcd000 r-xp 00000000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7bcd000-7ffff7dcd000 ---p 001c0000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dcd000-7ffff7dd1000 r--p 001c0000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dd1000-7ffff7dd3000 rw-p 001c4000 08:01 1054211                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dd3000-7ffff7dd7000 rw-p 00000000 00:00 0 
7ffff7dd7000-7ffff7dfd000 r-xp 00000000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7fba000-7ffff7fdf000 rw-p 00000000 00:00 0 
7ffff7ff7000-7ffff7ffa000 r--p 00000000 00:00 0                          [vvar]
7ffff7ffa000-7ffff7ffc000 r-xp 00000000 00:00 0                          [vdso]
7ffff7ffc000-7ffff7ffd000 r--p 00025000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7ffd000-7ffff7ffe000 rw-p 00026000 08:01 1053688                    /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0 
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

 ==================== END ====================
```
**分析**：

在调用`personality`之前，进行了两次`system("cat /proc/self/maps")`，所得到的输出中，
栈和动态链接库的基地址都是不同的，而当我们调用了`personality(ADDR_NO_RANDOMIZE)`之后，
同样做了两次`cat`得到的结果却是完全一致的。

## 思考

在CTF比赛中，合理利用`personality`，能够快速编写EXP，如以下场景：
- 能够ROP和有限制的mmap时，可利用`personality`导致新分配的内存块标记为可执行
- 当堆还未初始化时，利用`personality`，可导致堆可执行


## 引用

1. [personality(2) - Linux online manual page](http://man7.org/linux/man-pages/man2/personality.2.html)
2. [Searchable Linux Syscall Table for x86 and x86_64](https://filippo.io/linux-syscall-table/)