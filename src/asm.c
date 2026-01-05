#include "events_internal.h"

static void(fastcall *coro_swap)(tasks_t *, tasks_t *) = 0;
static EVENTS_INLINE void task_done(void);
static void task_awaitable(void);

#ifdef MPROTECT
alignas(4096)
#else
section(text)
#endif

#if ((defined(__clang__) || defined(__GNUC__)) && defined(__i386__)) || (defined(_MSC_VER) && defined(_M_IX86))
/* ABI: fastcall */
static const unsigned char coro_swap_function[4096] = {
	0x89, 0x22,       /* mov [edx],esp    */
	0x8b, 0x21,       /* mov esp,[ecx]    */
	0x58,             /* pop eax          */
	0x89, 0x6a, 0x04, /* mov [edx+ 4],ebp */
	0x89, 0x72, 0x08, /* mov [edx+ 8],esi */
	0x89, 0x7a, 0x0c, /* mov [edx+12],edi */
	0x89, 0x5a, 0x10, /* mov [edx+16],ebx */
	0x8b, 0x69, 0x04, /* mov ebp,[ecx+ 4] */
	0x8b, 0x71, 0x08, /* mov esi,[ecx+ 8] */
	0x8b, 0x79, 0x0c, /* mov edi,[ecx+12] */
	0x8b, 0x59, 0x10, /* mov ebx,[ecx+16] */
	0xff, 0xe0,       /* jmp eax          */
};

#ifdef _WIN32
#include <windows.h>
static void coro_init(void) {
#ifdef MPROTECT
	DWORD old_privileges;
	VirtualProtect((void *)coro_swap_function, sizeof coro_swap_function, PAGE_EXECUTE_READ, &old_privileges);
#endif
}
#else
#ifdef MPROTECT
#include <unistd.h>
#include <sys/mman.h>
#endif

static void coro_init(void) {
#ifdef MPROTECT
	unsigned long addr = (unsigned long)coro_swap_function;
	unsigned long base = addr - (addr % sysconf(_SC_PAGESIZE));
	unsigned long size = (addr - base) + sizeof coro_swap_function;
	mprotect((void *)base, size, PROT_READ | PROT_EXEC);
#endif
}
#endif

tasks_t *task_derive(void *memory, size_t size, bool is_thread) {
	(void)is_thread;
	tasks_t *handle;
	if (!coro_swap) {
		coro_init();
		coro_swap = (void(fastcall *)(tasks_t *, tasks_t *))coro_swap_function;
	}

	if ((handle = (tasks_t *)memory)) {
		unsigned long stack_top = (unsigned long)handle + size;
		stack_top -= 32;
		stack_top &= ~((unsigned long)15);
		long *p = (long *)(stack_top); /* seek to top of stack */
		*--p = (long)task_done;          /* if func returns */
		*--p = (long)task_awaitable;     /* start of function */
		*(long *)handle = (long)p;     /* stack pointer */
	}

	return handle;
}
#elif ((defined(__clang__) || defined(__GNUC__)) && defined(__amd64__)) || (defined(_MSC_VER) && defined(_M_AMD64))
#ifdef _WIN32
/* ABI: Win64 */
static const unsigned char coro_swap_function[4096] = {
	0x48, 0x89, 0x22,             /* mov [rdx],rsp           */
	0x48, 0x8b, 0x21,             /* mov rsp,[rcx]           */
	0x58,                         /* pop rax                 */
	0x48, 0x83, 0xe9, 0x80,       /* sub rcx,-0x80           */
	0x48, 0x83, 0xea, 0x80,       /* sub rdx,-0x80           */
	0x48, 0x89, 0x6a, 0x88,       /* mov [rdx-0x78],rbp      */
	0x48, 0x89, 0x72, 0x90,       /* mov [rdx-0x70],rsi      */
	0x48, 0x89, 0x7a, 0x98,       /* mov [rdx-0x68],rdi      */
	0x48, 0x89, 0x5a, 0xa0,       /* mov [rdx-0x60],rbx      */
	0x4c, 0x89, 0x62, 0xa8,       /* mov [rdx-0x58],r12      */
	0x4c, 0x89, 0x6a, 0xb0,       /* mov [rdx-0x50],r13      */
	0x4c, 0x89, 0x72, 0xb8,       /* mov [rdx-0x48],r14      */
	0x4c, 0x89, 0x7a, 0xc0,       /* mov [rdx-0x40],r15      */
#if !defined(NO_SSE)
		0x0f, 0x29, 0x72, 0xd0,       /* movaps [rdx-0x30],xmm6  */
		0x0f, 0x29, 0x7a, 0xe0,       /* movaps [rdx-0x20],xmm7  */
		0x44, 0x0f, 0x29, 0x42, 0xf0, /* movaps [rdx-0x10],xmm8  */
		0x44, 0x0f, 0x29, 0x0a,       /* movaps [rdx],     xmm9  */
		0x44, 0x0f, 0x29, 0x52, 0x10, /* movaps [rdx+0x10],xmm10 */
		0x44, 0x0f, 0x29, 0x5a, 0x20, /* movaps [rdx+0x20],xmm11 */
		0x44, 0x0f, 0x29, 0x62, 0x30, /* movaps [rdx+0x30],xmm12 */
		0x44, 0x0f, 0x29, 0x6a, 0x40, /* movaps [rdx+0x40],xmm13 */
		0x44, 0x0f, 0x29, 0x72, 0x50, /* movaps [rdx+0x50],xmm14 */
		0x44, 0x0f, 0x29, 0x7a, 0x60, /* movaps [rdx+0x60],xmm15 */
#endif
		0x48, 0x8b, 0x69, 0x88,       /* mov rbp,[rcx-0x78]      */
		0x48, 0x8b, 0x71, 0x90,       /* mov rsi,[rcx-0x70]      */
		0x48, 0x8b, 0x79, 0x98,       /* mov rdi,[rcx-0x68]      */
		0x48, 0x8b, 0x59, 0xa0,       /* mov rbx,[rcx-0x60]      */
		0x4c, 0x8b, 0x61, 0xa8,       /* mov r12,[rcx-0x58]      */
		0x4c, 0x8b, 0x69, 0xb0,       /* mov r13,[rcx-0x50]      */
		0x4c, 0x8b, 0x71, 0xb8,       /* mov r14,[rcx-0x48]      */
		0x4c, 0x8b, 0x79, 0xc0,       /* mov r15,[rcx-0x40]      */
#if !defined(NO_SSE)
		0x0f, 0x28, 0x71, 0xd0,       /* movaps xmm6, [rcx-0x30] */
		0x0f, 0x28, 0x79, 0xe0,       /* movaps xmm7, [rcx-0x20] */
		0x44, 0x0f, 0x28, 0x41, 0xf0, /* movaps xmm8, [rcx-0x10] */
		0x44, 0x0f, 0x28, 0x09,       /* movaps xmm9, [rcx]      */
		0x44, 0x0f, 0x28, 0x51, 0x10, /* movaps xmm10,[rcx+0x10] */
		0x44, 0x0f, 0x28, 0x59, 0x20, /* movaps xmm11,[rcx+0x20] */
		0x44, 0x0f, 0x28, 0x61, 0x30, /* movaps xmm12,[rcx+0x30] */
		0x44, 0x0f, 0x28, 0x69, 0x40, /* movaps xmm13,[rcx+0x40] */
		0x44, 0x0f, 0x28, 0x71, 0x50, /* movaps xmm14,[rcx+0x50] */
		0x44, 0x0f, 0x28, 0x79, 0x60, /* movaps xmm15,[rcx+0x60] */
#endif
#if !defined(NO_TIB)
		0x65, 0x4c, 0x8b, 0x04, 0x25, /* mov r8,gs:0x30          */
		0x30, 0x00, 0x00, 0x00,
		0x41, 0x0f, 0x10, 0x40, 0x08, /* movups xmm0,[r8+0x8]    */
		0x0f, 0x29, 0x42, 0x70,       /* movaps [rdx+0x70],xmm0  */
		0x0f, 0x28, 0x41, 0x70,       /* movaps xmm0,[rcx+0x70]  */
		0x41, 0x0f, 0x11, 0x40, 0x08, /* movups [r8+0x8],xmm0    */
#endif
		0xff, 0xe0,                   /* jmp rax                 */
};

#include <windows.h>

static void coro_init(void) {
#ifdef MPROTECT
	DWORD old_privileges;
	VirtualProtect((void *)coro_swap_function, sizeof coro_swap_function, PAGE_EXECUTE_READ, &old_privileges);
#endif
}
#else
/* ABI: SystemV */
static const unsigned char coro_swap_function[4096] = {
	0x48, 0x89, 0x26,       /* mov [rsi],rsp    */
	0x48, 0x8b, 0x27,       /* mov rsp,[rdi]    */
	0x58,                   /* pop rax          */
	0x48, 0x89, 0x6e, 0x08, /* mov [rsi+ 8],rbp */
	0x48, 0x89, 0x5e, 0x10, /* mov [rsi+16],rbx */
	0x4c, 0x89, 0x66, 0x18, /* mov [rsi+24],r12 */
	0x4c, 0x89, 0x6e, 0x20, /* mov [rsi+32],r13 */
	0x4c, 0x89, 0x76, 0x28, /* mov [rsi+40],r14 */
	0x4c, 0x89, 0x7e, 0x30, /* mov [rsi+48],r15 */
	0x48, 0x8b, 0x6f, 0x08, /* mov rbp,[rdi+ 8] */
	0x48, 0x8b, 0x5f, 0x10, /* mov rbx,[rdi+16] */
	0x4c, 0x8b, 0x67, 0x18, /* mov r12,[rdi+24] */
	0x4c, 0x8b, 0x6f, 0x20, /* mov r13,[rdi+32] */
	0x4c, 0x8b, 0x77, 0x28, /* mov r14,[rdi+40] */
	0x4c, 0x8b, 0x7f, 0x30, /* mov r15,[rdi+48] */
	0xff, 0xe0,             /* jmp rax          */
};

#ifdef MPROTECT
#include <unistd.h>
#include <sys/mman.h>
#endif

static void coro_init(void) {
#ifdef MPROTECT
	unsigned long long addr = (unsigned long long)coro_swap_function;
	unsigned long long base = addr - (addr % sysconf(_SC_PAGESIZE));
	unsigned long long size = (addr - base) + sizeof coro_swap_function;
	mprotect((void *)base, size, PROT_READ | PROT_EXEC);
#endif
}
#endif
tasks_t *task_derive(void *memory, size_t size, bool is_thread) {
	(void)is_thread;
	tasks_t *handle;
	if (!coro_swap) {
		coro_init();
		coro_swap = (void (*)(tasks_t *, tasks_t *))coro_swap_function;
	}

	if ((handle = (tasks_t *)memory)) {
		size_t stack_top = (size_t)handle + size;
		stack_top -= 32;
		stack_top &= ~((size_t)15);
		int64_t *p = (int64_t *)(stack_top); /* seek to top of stack */
		*--p = (int64_t)task_done;               /* if coroutine returns */
		*--p = (int64_t)task_awaitable;
		*(int64_t *)handle = (int64_t)p;                  /* stack pointer */
#if defined(_WIN32) && !defined(NO_TIB)
		((int64_t *)handle)[30] = (int64_t)handle + size; /* stack base */
		((int64_t *)handle)[31] = (int64_t)handle;        /* stack limit */
#endif
	}

	return handle;
}
#elif defined(__clang__) || defined(__GNUC__)
#if defined(__arm__)
#ifdef MPROTECT
#include <unistd.h>
#include <sys/mman.h>
#endif

static const size_t coro_swap_function[1024] = {
	0xe8a16ff0, /* stmia r1!, {r4-r11,sp,lr} */
	0xe8b0aff0, /* ldmia r0!, {r4-r11,sp,pc} */
	0xe12fff1e, /* bx lr                     */
};

static void coro_init(void) {
#ifdef MPROTECT
	size_t addr = (size_t)coro_swap_function;
	size_t base = addr - (addr % sysconf(_SC_PAGESIZE));
	size_t size = (addr - base) + sizeof coro_swap_function;
	mprotect((void *)base, size, PROT_READ | PROT_EXEC);
#endif
}

tasks_t *task_derive(void *memory, size_t size, bool is_thread) {
	(void)is_thread;
	size_t *handle;
	tasks_t *co;
	if (!coro_swap) {
		coro_init();
		coro_swap = (void (*)(tasks_t *, tasks_t *))coro_swap_function;
	}

	if ((handle = (size_t *)memory)) {
		size_t stack_top = (size_t)handle + size;
		stack_top &= ~((size_t)15);
		size_t *p = (size_t *)(stack_top);
		handle[8] = (size_t)p;
		handle[9] = (size_t)coro_func;

		co = (tasks_t *)handle;
	}

	return co;
}
#elif defined(__aarch64__)
static const uint32_t coro_swap_function[1024] = {
	0x910003f0, /* mov x16,sp           */
	0xa9007830, /* stp x16,x30,[x1]     */
	0xa9407810, /* ldp x16,x30,[x0]     */
	0x9100021f, /* mov sp,x16           */
	0xa9015033, /* stp x19,x20,[x1, 16] */
	0xa9415013, /* ldp x19,x20,[x0, 16] */
	0xa9025835, /* stp x21,x22,[x1, 32] */
	0xa9425815, /* ldp x21,x22,[x0, 32] */
	0xa9036037, /* stp x23,x24,[x1, 48] */
	0xa9436017, /* ldp x23,x24,[x0, 48] */
	0xa9046839, /* stp x25,x26,[x1, 64] */
	0xa9446819, /* ldp x25,x26,[x0, 64] */
	0xa905703b, /* stp x27,x28,[x1, 80] */
	0xa945701b, /* ldp x27,x28,[x0, 80] */
	0xf900303d, /* str x29,    [x1, 96] */
	0xf940301d, /* ldr x29,    [x0, 96] */
	0x6d072428, /* stp d8, d9, [x1,112] */
	0x6d472408, /* ldp d8, d9, [x0,112] */
	0x6d082c2a, /* stp d10,d11,[x1,128] */
	0x6d482c0a, /* ldp d10,d11,[x0,128] */
	0x6d09342c, /* stp d12,d13,[x1,144] */
	0x6d49340c, /* ldp d12,d13,[x0,144] */
	0x6d0a3c2e, /* stp d14,d15,[x1,160] */
	0x6d4a3c0e, /* ldp d14,d15,[x0,160] */
#if defined(_WIN32) && !defined(NO_TIB)
	0xa940c650, /* ldp x16,x17,[x18, 8] */
	0xa90b4430, /* stp x16,x17,[x1,176] */
	0xa94b4410, /* ldp x16,x17,[x0,176] */
	0xa900c650, /* stp x16,x17,[x18, 8] */
#endif
	0xd61f03c0, /* br x30               */
};

#ifdef _WIN32
#include <windows.h>

static void coro_init(void) {
#ifdef MPROTECT
	DWORD old_privileges;
	VirtualProtect((void *)coro_swap_function, sizeof coro_swap_function, PAGE_EXECUTE_READ, &old_privileges);
#endif
}
#else
#ifdef MPROTECT
#include <unistd.h>
#include <sys/mman.h>
#endif

static void coro_init(void) {
#ifdef MPROTECT
	size_t addr = (size_t)coro_swap_function;
	size_t base = addr - (addr % sysconf(_SC_PAGESIZE));
	size_t size = (addr - base) + sizeof coro_swap_function;
	mprotect((void *)base, size, PROT_READ | PROT_EXEC);
#endif
}
#endif

tasks_t *task_derive(void *memory, size_t size, bool is_thread) {
	(void)is_thread;
	size_t *handle;
	tasks_t *co;
	if (!coro_swap) {
		coro_init();
		coro_swap = (void (*)(tasks_t *, tasks_t *))coro_swap_function;
	}

	if ((handle = (size_t *)memory)) {
		size_t stack_top = (size_t)handle + size;
		stack_top &= ~((size_t)15);
		size_t *p = (size_t *)(stack_top);
		handle[0] = (size_t)p;              /* x16 (stack pointer) */
		handle[1] = (size_t)coro_func;        /* x30 (link register) */
		handle[12] = (size_t)p;             /* x29 (frame pointer) */

#if defined(_WIN32) && !defined(NO_TIB)
		handle[22] = (size_t)handle + size; /* stack base */
		handle[23] = (size_t)handle;        /* stack limit */
#endif

		co = (tasks_t *)handle;
	}

	return co;
}
#elif defined(__powerpc64__) && defined(_CALL_ELF) && _CALL_ELF == 2
static void coro_init(void) {}

void swap_context(tasks_t *read, tasks_t *write);
__asm__(
	".text\n"
	".align 4\n"
	".type swap_context @function\n"
	"swap_context:\n"
	".cfi_startproc\n"

	/* save GPRs */
	"std 1, 8(4)\n"
	"std 2, 16(4)\n"
	"std 12, 96(4)\n"
	"std 13, 104(4)\n"
	"std 14, 112(4)\n"
	"std 15, 120(4)\n"
	"std 16, 128(4)\n"
	"std 17, 136(4)\n"
	"std 18, 144(4)\n"
	"std 19, 152(4)\n"
	"std 20, 160(4)\n"
	"std 21, 168(4)\n"
	"std 22, 176(4)\n"
	"std 23, 184(4)\n"
	"std 24, 192(4)\n"
	"std 25, 200(4)\n"
	"std 26, 208(4)\n"
	"std 27, 216(4)\n"
	"std 28, 224(4)\n"
	"std 29, 232(4)\n"
	"std 30, 240(4)\n"
	"std 31, 248(4)\n"

	/* save LR */
	"mflr 5\n"
	"std 5, 256(4)\n"

	/* save CCR */
	"mfcr 5\n"
	"std 5, 264(4)\n"

	/* save FPRs */
	"stfd 14, 384(4)\n"
	"stfd 15, 392(4)\n"
	"stfd 16, 400(4)\n"
	"stfd 17, 408(4)\n"
	"stfd 18, 416(4)\n"
	"stfd 19, 424(4)\n"
	"stfd 20, 432(4)\n"
	"stfd 21, 440(4)\n"
	"stfd 22, 448(4)\n"
	"stfd 23, 456(4)\n"
	"stfd 24, 464(4)\n"
	"stfd 25, 472(4)\n"
	"stfd 26, 480(4)\n"
	"stfd 27, 488(4)\n"
	"stfd 28, 496(4)\n"
	"stfd 29, 504(4)\n"
	"stfd 30, 512(4)\n"
	"stfd 31, 520(4)\n"

#ifdef __ALTIVEC__
	/* save VMX */
	"li 5, 528\n"
	"stvxl 20, 4, 5\n"
	"addi 5, 5, 16\n"
	"stvxl 21, 4, 5\n"
	"addi 5, 5, 16\n"
	"stvxl 22, 4, 5\n"
	"addi 5, 5, 16\n"
	"stvxl 23, 4, 5\n"
	"addi 5, 5, 16\n"
	"stvxl 24, 4, 5\n"
	"addi 5, 5, 16\n"
	"stvxl 25, 4, 5\n"
	"addi 5, 5, 16\n"
	"stvxl 26, 4, 5\n"
	"addi 5, 5, 16\n"
	"stvxl 27, 4, 5\n"
	"addi 5, 5, 16\n"
	"stvxl 28, 4, 5\n"
	"addi 5, 5, 16\n"
	"stvxl 29, 4, 5\n"
	"addi 5, 5, 16\n"
	"stvxl 30, 4, 5\n"
	"addi 5, 5, 16\n"
	"stvxl 31, 4, 5\n"
	"addi 5, 5, 16\n"

	/* save VRSAVE */
	"mfvrsave 5\n"
	"stw 5, 736(4)\n"
#endif

	/* restore GPRs */
	"ld 1, 8(3)\n"
	"ld 2, 16(3)\n"
	"ld 12, 96(3)\n"
	"ld 13, 104(3)\n"
	"ld 14, 112(3)\n"
	"ld 15, 120(3)\n"
	"ld 16, 128(3)\n"
	"ld 17, 136(3)\n"
	"ld 18, 144(3)\n"
	"ld 19, 152(3)\n"
	"ld 20, 160(3)\n"
	"ld 21, 168(3)\n"
	"ld 22, 176(3)\n"
	"ld 23, 184(3)\n"
	"ld 24, 192(3)\n"
	"ld 25, 200(3)\n"
	"ld 26, 208(3)\n"
	"ld 27, 216(3)\n"
	"ld 28, 224(3)\n"
	"ld 29, 232(3)\n"
	"ld 30, 240(3)\n"
	"ld 31, 248(3)\n"

	/* restore LR */
	"ld 5, 256(3)\n"
	"mtlr 5\n"

	/* restore CCR */
	"ld 5, 264(3)\n"
	"mtcr 5\n"

	/* restore FPRs */
	"lfd 14, 384(3)\n"
	"lfd 15, 392(3)\n"
	"lfd 16, 400(3)\n"
	"lfd 17, 408(3)\n"
	"lfd 18, 416(3)\n"
	"lfd 19, 424(3)\n"
	"lfd 20, 432(3)\n"
	"lfd 21, 440(3)\n"
	"lfd 22, 448(3)\n"
	"lfd 23, 456(3)\n"
	"lfd 24, 464(3)\n"
	"lfd 25, 472(3)\n"
	"lfd 26, 480(3)\n"
	"lfd 27, 488(3)\n"
	"lfd 28, 496(3)\n"
	"lfd 29, 504(3)\n"
	"lfd 30, 512(3)\n"
	"lfd 31, 520(3)\n"

#ifdef __ALTIVEC__
	/* restore VMX */
	"li 5, 528\n"
	"lvxl 20, 3, 5\n"
	"addi 5, 5, 16\n"
	"lvxl 21, 3, 5\n"
	"addi 5, 5, 16\n"
	"lvxl 22, 3, 5\n"
	"addi 5, 5, 16\n"
	"lvxl 23, 3, 5\n"
	"addi 5, 5, 16\n"
	"lvxl 24, 3, 5\n"
	"addi 5, 5, 16\n"
	"lvxl 25, 3, 5\n"
	"addi 5, 5, 16\n"
	"lvxl 26, 3, 5\n"
	"addi 5, 5, 16\n"
	"lvxl 27, 3, 5\n"
	"addi 5, 5, 16\n"
	"lvxl 28, 3, 5\n"
	"addi 5, 5, 16\n"
	"lvxl 29, 3, 5\n"
	"addi 5, 5, 16\n"
	"lvxl 30, 3, 5\n"
	"addi 5, 5, 16\n"
	"lvxl 31, 3, 5\n"
	"addi 5, 5, 16\n"

	/* restore VRSAVE */
	"lwz 5, 720(3)\n"
	"mtvrsave 5\n"
#endif

	/* branch to LR */
	"blr\n"

	".cfi_endproc\n"
	".size swap_context, .-swap_context\n");

tasks_t *task_derive(void *memory, size_t size, bool is_thread) {
	(void)is_thread;
	uint8_t *sp;
	tasks_t *context = (tasks_t *)memory;
	if (!coro_swap) {
		coro_swap = (void (*)(tasks_t *, tasks_t *))swap_context;
	}

	/* save current context into new context to initialize it */
	swap_context(context, context);

	/* align stack */
	sp = (uint8_t *)memory + size - STACK_PPC_ALIGN;
	sp = (uint8_t *)PPC_ALIGN(sp, STACK_PPC_ALIGN);

	/* write 0 for initial backchain */
	*(uint64_t *)sp = 0;

	/* create new frame with backchain */
	sp -= PPC_MIN_STACK_FRAME;
	*(uint64_t *)sp = (uint64_t)(sp + PPC_MIN_STACK_FRAME);

	/* update context with new stack (r1) and func (r12, lr) */
	((coroutine_t *)context)->gprs[1] = (uint64_t)sp;
	((coroutine_t *)context)->gprs[12] = (uint64_t)coro_func;
	((coroutine_t *)context)->lr = (uint64_t)coro_func;

	return (tasks_t *)memory;
}

#elif defined(__ARM_EABI__)
void swap_context(tasks_t *from, tasks_t *to);
__asm__(
	".text\n"
#ifdef __APPLE__
	".globl _swap_context\n"
	"_swap_context:\n"
#else
	".globl swap_context\n"
	".type swap_context #function\n"
	".hidden swap_context\n"
	"swap_context:\n"
#endif

#ifndef __SOFTFP__
	"vstmia r0!, {d8-d15}\n"
#endif
	"stmia r0, {r4-r11, lr}\n"
	".byte 0xE5, 0x80,  0xD0, 0x24\n" /* should be "str sp, [r0, #9*4]\n", it's causing vscode display issue */
#ifndef __SOFTFP__
	"vldmia r1!, {d8-d15}\n"
#endif
	".byte 0xE5, 0x91, 0xD0, 0x24\n" /* should be "ldr sp, [r1, #9*4]\n", it's causing vscode display issue */
	"ldmia r1, {r4-r11, pc}\n"
#ifndef __APPLE__
	".size swap_context, .-swap_context\n"
#endif
);

static void coro_init(void) {}

tasks_t *task_derive(void *memory, size_t size, bool is_thread) {
	(void)is_thread;
	coroutine_t *ctx = (coroutine_t *)memory;
	if (!coro_swap) {
		coro_swap = (void (*)(tasks_t *, tasks_t *))swap_context;
	}

	ctx->d[0] = memory;
	ctx->d[1] = (void *)(task_awaitable);
	ctx->d[2] = (void *)(task_done);
	ctx->lr = (void *)(task_awaitable);
	ctx->sp = (void *)((size_t)memory + size);

	return (tasks_t *)memory;
}

#elif defined(__riscv)
#if __riscv_xlen == 32
#   define I_STORE "sw"
#   define I_LOAD  "lw"
#elif __riscv_xlen == 64
#   define I_STORE "sd"
#   define I_LOAD  "ld"
#else
#   error Unsupported RISC-V XLEN
#endif

#if !defined(__riscv_flen)
#   define F_STORE "#"
#   define F_LOAD  "#"
#elif __riscv_flen == 32
#   define F_STORE "fsw"
#   define F_LOAD  "flw"
#elif __riscv_flen == 64
#   define F_STORE "fsd"
#   define F_LOAD  "fld"
#else
#   error Unsupported RISC-V FLEN
#endif

__attribute__((naked))
static void swap_context(tasks_t *active, tasks_t *previous) {
	__asm__(
		I_STORE " ra,   0 *8(a1)\n"
		I_STORE " sp,   1 *8(a1)\n"
		I_STORE " s0,   2 *8(a1)\n"
		I_STORE " s1,   3 *8(a1)\n"
		I_STORE " s2,   4 *8(a1)\n"
		I_STORE " s3,   5 *8(a1)\n"
		I_STORE " s4,   6 *8(a1)\n"
		I_STORE " s5,   7 *8(a1)\n"
		I_STORE " s6,   8 *8(a1)\n"
		I_STORE " s7,   9 *8(a1)\n"
		I_STORE " s8,   10*8(a1)\n"
		I_STORE " s9,   11*8(a1)\n"
		I_STORE " s10,  12*8(a1)\n"
		I_STORE " s11,  13*8(a1)\n"

		F_STORE " fs0,  14*8(a1)\n"
		F_STORE " fs1,  15*8(a1)\n"
		F_STORE " fs2,  16*8(a1)\n"
		F_STORE " fs3,  17*8(a1)\n"
		F_STORE " fs4,  18*8(a1)\n"
		F_STORE " fs5,  19*8(a1)\n"
		F_STORE " fs6,  20*8(a1)\n"
		F_STORE " fs7,  21*8(a1)\n"
		F_STORE " fs8,  22*8(a1)\n"
		F_STORE " fs9,  23*8(a1)\n"
		F_STORE " fs10, 24*8(a1)\n"
		F_STORE " fs11, 25*8(a1)\n"

		I_LOAD  " ra,   0 *8(a0)\n"
		I_LOAD  " sp,   1 *8(a0)\n"
		I_LOAD  " s0,   2 *8(a0)\n"
		I_LOAD  " s1,   3 *8(a0)\n"
		I_LOAD  " s2,   4 *8(a0)\n"
		I_LOAD  " s3,   5 *8(a0)\n"
		I_LOAD  " s4,   6 *8(a0)\n"
		I_LOAD  " s5,   7 *8(a0)\n"
		I_LOAD  " s6,   8 *8(a0)\n"
		I_LOAD  " s7,   9 *8(a0)\n"
		I_LOAD  " s8,   10*8(a0)\n"
		I_LOAD  " s9,   11*8(a0)\n"
		I_LOAD  " s10,  12*8(a0)\n"
		I_LOAD  " s11,  13*8(a0)\n"

		F_LOAD  " fs0,  14*8(a0)\n"
		F_LOAD  " fs1,  15*8(a0)\n"
		F_LOAD  " fs2,  16*8(a0)\n"
		F_LOAD  " fs3,  17*8(a0)\n"
		F_LOAD  " fs4,  18*8(a0)\n"
		F_LOAD  " fs5,  19*8(a0)\n"
		F_LOAD  " fs6,  20*8(a0)\n"
		F_LOAD  " fs7,  21*8(a0)\n"
		F_LOAD  " fs8,  22*8(a0)\n"
		F_LOAD  " fs9,  23*8(a0)\n"
		F_LOAD  " fs10, 24*8(a0)\n"
		F_LOAD  " fs11, 25*8(a0)\n"

		"ret\n"
	);
}

static void coro_init(void) {}

tasks_t *task_derive(void *memory, size_t size, bool is_thread) {
	(void)is_thread;
	uint64_t *handle;
	if (!coro_swap) {
		coro_swap = (void (*)(tasks_t *, tasks_t *))swap_context;
	}

	if (handle = (uint64_t *)memory) {
		unsigned int offset = (size & ~15);
		uint64_t *p = (uint64_t *)((uint8_t *)handle + offset);
		*(uintptr_t *)&handle[0] = (uintptr_t)coro_func;    // ra (return address)
		*(uintptr_t *)&handle[1] = (uintptr_t)p;            // sp (stack pointer)
		*(uintptr_t *)&handle[2] = (uintptr_t)p;            // s0 (frame pointer)
		*(uintptr_t *)&handle[3] = (uintptr_t)coro_func;    // s1 (entry point)
	}

	return (tasks_t *)handle;
}

#endif
#endif