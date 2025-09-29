global ASM_entry

section .text
ASM_entry:
	; int3
	;; Set RFlags
	push QWORD 0x2
	popfq

	mov r12, rdx	;; (2) rdx - entry point
	mov rsp, rsi	;; (1) rsi - stack
	mov rdx, rdi	;; (0) rdi - rdx value at program startup
	xor rbp, rbp
	
	jmp clear_regs
entry:
	jmp r12

clear_regs:
	xor rax, rax
	xor rbx, rbx
	xor rcx, rcx
	xor rdi, rdi
	xor rsi, rsi
	xor r8,	r8
	xor r9, r9
	xor r10, r10
	xor r11, r11
	xor r13, r13
	xor r14, r14
	xor r15, r15
	jmp entry