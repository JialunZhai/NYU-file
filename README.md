# NYU-file: Need You to Undelete my FILE

## A FAT32 file recovery tool

## Background

FAT32 has been around for 25 years. Because of its simplicity, it is the most widely compatible file system. Although recent computers have adopted newer file systems, FAT32 is still dominant in SD cards and USB flash drives due to its compatibility.

Have you ever accidentally deleted a file? Do you know that it could be recovered? NYUfile is a FAT32 file recovery tool to recover your file from a raw disk.

But wait a minute, when you delete some files by accident, do you know what's the first thing you need to do? The answer is "plug out the charge cord of your computer" or "press on the battery button of your laptop" as quickly as you can. Why? That is to prevent the OS from overwriting your deleted file.

Not all files can be recovered successfully. Sometimes you need to provide extra information to help the recovery tool indentify your file. And sometimes we need a brute-force search to put the pieces of your file, namely the clusters, together and try all the possible combinations of these pieces to check whether they can form you original file. This implies that we may not be able to recover the file in pratice even though there is a possiblility in theory.

In short, FAT32 is not a file-system designed for file recovery. There is some thing we can do to recover a file, but to a limited extent. If file recovery really matters, you need to try other file-systems.

## Enviroment

This tool is built on **Linux** with **C++11** language. It also relies on OpenSSL library to compute SHA-1 digest of a file. Please make sure you have installed **OpenSSL** before compilation.

## Compilation

If you have installed CMake on your Linux System, you can directly run command `make` to compile; Otherwise, you should run command

`g++ nyufile.cpp -std=c++11 -o nyufile -l crypto`

to compile.
If you compiled successfully, you will see an executable file named **nyufile** in current directory. Then you can run command `./nyufile` to open the tool.

## Usage

### Open the tool with usage printed

```bash
$ ./nyufile
Usage: ./nyufile disk <options>
-i Print the file system information.
-l List the root directory.
-r filename [-s sha1] Recover a contiguous file.
-R filename -s sha1 Recover a possibly non-contiguous file.
```

### Print the file system information

Suppose the disk your want to recover named _fat32.disk_.

```bash
$ ./nyufile fat32.disk -i
Number of FATs = 2
Number of bytes per sector = 512
Number of sectors per cluster = 1
Number of reserved sectors = 32
```

### List the root directory

Suppose the disk your want to recover named _fat32.disk_.

```bash
$ ./nyufile fat32.disk -l
HELLO.TXT (size = 14, starting cluster = 3)
DIR/ (size = 0, starting cluster = 4)
EMPTY (size = 0, starting cluster = 0)
Total number of entries = 3
```

### Recover a contiguously-allocated file

**Note**: If you don't know whether your file is contiguously-allocated or not, try this option first.

**Succeeded**: Try to recover a file named _HELLO.TXT_ in disk _fat32.disk_ and successfully recovered.

```bash
$ ./nyufile fat32.disk -r HELLO.TXT
HELLO.TXT: successfully recovered
```

**Failed**: Try to recover a file named _HELLO_ in disk _fat32.disk_ while no file found.

```bash
$ ./nyufile fat32.disk -r HELLO
HELLO: file not found
```

**Failed but not really failed**: Try to recover a file named _TANT.TXT_ in disk _fat32.disk_ but mutiple files named _.ANG.TXT_ are detected. The recover tool doesn't know which one you want to recover, therefore, you need to provide extra information about the file you want to recover, i.e., SHA-1 digest.

```bash
$ ./nyufile fat32.disk -r TANG.TXT
TANG.TXT: multiple candidates found
```

### Recover a contiguously-allocated file with SHA-1 hash

**Note**: This option will perform a brute force algorithm.  To avoid endless search, **only the first 12 clusters of the disk will be searched**.

**Succeeded**: Try to recover a file named _TANG.TXT_ with SHA-1 hash _c91761a2cc1562d36585614c8c680ecf5712_ in disk _fat32.disk_ and successfully recovered.

```bash
$ ./nyufile fat32.disk -r TANG.TXT -s c91761a2cc1562d36585614c8c680ecf5712
TANG.TXT: successfully recovered with SHA-1
```

**Failed**: Try to recover a file named _TANG.TXT_ with SHA-1 hash _0123456789abcdef0123456789abcdef0123_ in disk _fat32.disk_ while no file found.

```bash
$ ./nyufile fat32.disk -r TANG.TXT -s 0123456789abcdef0123456789abcdef0123
TANG.TXT: file not found
```

## Acknowledgement

This project came from course **Operating Systems (CSCI-GA.2250-002)** in **NYU**, offered by **Prof. Yang Tang**.
