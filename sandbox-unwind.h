#ifndef _ASM_SANDBOX_UNWIND_H
#define _ASM_SANDBOX_UNWIND_H

#include <linux/sched.h>
#include <linux/hashtable.h>

#define DEBUG_SANDBOX 0
#define FIXME_SANDBOX 1
#define DEBUG_SO_INFO 0

#define TERMINATE_FUNCTION "main"

#ifdef TERMINATE_FUNCTION
#undef NEED_SYMBOLS
#define NEED_SYMBOLS 1

#else
#define NEED_SYMBOLS 0

#endif // TERMINATE_FUNCTION

#define UNW_REGISTER_INFO \
	PTREGS_INFO(x0), \
	PTREGS_INFO(x1), \
	PTREGS_INFO(x2), \
	PTREGS_INFO(x3), \
	PTREGS_INFO(x4), \
	PTREGS_INFO(x5), \
	PTREGS_INFO(x6), \
	PTREGS_INFO(x7), \
	PTREGS_INFO(x8), \
	PTREGS_INFO(x9), \
	PTREGS_INFO(x10), \
	PTREGS_INFO(x11), \
	PTREGS_INFO(x12), \
	PTREGS_INFO(x13), \
	PTREGS_INFO(x14), \
	PTREGS_INFO(x15), \
	PTREGS_INFO(x16), \
	PTREGS_INFO(x17), \
	PTREGS_INFO(x18), \
	PTREGS_INFO(x19), \
	PTREGS_INFO(x20), \
	PTREGS_INFO(x21), \
	PTREGS_INFO(x22), \
	PTREGS_INFO(x23), \
	PTREGS_INFO(x24), \
	PTREGS_INFO(x25), \
	PTREGS_INFO(x26), \
	PTREGS_INFO(x27), \
	PTREGS_INFO(x28), \
	PTREGS_INFO(x29), \
	PTREGS_INFO(x30), \
	PTREGS_INFO(sp), \
	PTREGS_INFO(pc), \
	PTREGS_INFO(pstate)

#define UNW_DEFAULT_RA(raItem, dataAlign) \
	((raItem).where == Memory && !((raItem).value * (dataAlign) + 4))

#define STACK_LIMIT(ptr) (((ptr)-1) & ~(THREAD_SIZE - 1))
/*
Reference:
https://developer.arm.com/documentation/den0024/a/ARMv8-Registers
*/
struct armv8_regs {
	unsigned long x0;
	unsigned long x1;
	unsigned long x2;
	unsigned long x3;
	unsigned long x4;
	unsigned long x5;
	unsigned long x6;
	unsigned long x7;
	unsigned long x8;
	unsigned long x9;
	unsigned long x10;
	unsigned long x11;
	unsigned long x12;
	unsigned long x13;
	unsigned long x14;
	unsigned long x15;
	unsigned long x16;
	unsigned long x17;
	unsigned long x18;
	unsigned long x19;
	unsigned long x20;
	unsigned long x21;
	unsigned long x22;
	unsigned long x23;
	unsigned long x24;
	unsigned long x25;
	unsigned long x26;
	unsigned long x27;
	unsigned long x28;
	unsigned long x29;
	unsigned long x30;
	unsigned long sp;
	unsigned long pc;
	unsigned long pstate;
};

struct unwind_frame_info {
	struct armv8_regs regs;
	struct task_struct *task;
	unsigned call_frame:1;
	unsigned long entry_point;
	unsigned long base_addr;
};

/**
 * struct unwind_table - metadata for the exe, or a .so
 * @address     : the start address of the kernel buffer containing the .eh_frame
 * @size        : size of the table
 * @header      : .eh_frame header
 * @hdrsz       : .eh_frame header size
 * @base_address: 0 if this's for the executable, or the base address
 *                of a shared object is the memory layout
 * @name        : name for the shared object
 * @next        : A pointer to the next table
 * @prev        : A pointer to the previous table
 * This structure is for metadata the exe, or a .so
 */
typedef struct unwind_table {
	struct {
		unsigned long pc;
		unsigned long range;
	} core, init;
	const void *address;
	unsigned long size;
	const unsigned char *header;
	unsigned long hdrsz;
	char name[TASK_COMM_LEN];
	const struct so_info *info;
	const void **state_cache; 

	struct unwind_table *next, *prev;
} table_t;

struct hash_table {
	pid_t pid;
	char *name;
	short is_filled, is_inited, elf_entry_found;
	unsigned long elf_entry, clone_entry, child_main;
	atomic_t *cntr;
	table_t *root_table;
	struct hlist_node node;
	DECLARE_HASHTABLE(htable, 16);
};

/**
 * so_info - information of shared object or binary
 * @base_address  : the base address of SO or binary
 * @eh_frame_size : the size of .eh_frame
 * @eh_frame_start: the offset of .eh_frame
 * @eh_frame_found: found .eh_frame or not
 * @plt_size      : the size of .plt
 * @plt_start     : the offset of .plt
 * @plt_found     : found .plt or not
 * @pc_range      : the range of executable memory
 * @ehframe       : the character buffer of the .eh_frame
 * @name          : the filename
*/
struct so_info {
	const char *ehframe;
	char *name;
	unsigned long base_address, eh_frame_size, eh_frame_start, plt_size,
		plt_start, pc_range;
	short eh_frame_found, plt_found;
	struct hlist_node node;
};

#define UNW_PC(frame) ((frame)->regs.pc)
#define UNW_SP(frame) ((frame)->regs.sp)

#define RELEASE_MEMORY(ptr)                 \
	{                                   \
		do {                        \
			if (ptr) {          \
				kfree(ptr); \
				ptr = NULL; \
			}                   \
		} while (0);                \
	}

void init_unwind_table(struct hash_table *, struct unwind_frame_info *);
void deinit_unwind_table(struct hash_table *, int);
int delta_unwind(struct hash_table *, struct unwind_frame_info *);
int delta_enforce_verification(struct hash_table *, struct unwind_frame_info *);
#endif
