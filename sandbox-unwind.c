#include <linux/printk.h>
#include <linux/kallsyms.h>
/* #include <asm/sandbox-unwind.h> */
#include "sandbox-unwind.h"
#include <linux/sort.h>
#include <asm/sections.h>
#include <asm/unaligned.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/miscdevice.h>
#include <linux/kprobes.h>

#define SANDBOX_VERSION "0.1"
#define OURMODNAME "sandbox-unwind"

#define MAX_STACK_DEPTH 8

#define EXTRA_INFO(f) { \
		BUILD_BUG_ON_ZERO(offsetof(struct unwind_frame_info, f) \
				% sizeof_field(struct unwind_frame_info, f)) \
				+ offsetof(struct unwind_frame_info, f) \
				/ sizeof_field(struct unwind_frame_info, f), \
				sizeof_field(struct unwind_frame_info, f) \
	}
#define PTREGS_INFO(f) EXTRA_INFO(regs.f)

static const struct {
	unsigned offs:BITS_PER_LONG / 2;
	unsigned width:BITS_PER_LONG / 2;
} reg_info[] = {
UNW_REGISTER_INFO};

#undef PTREGS_INFO
#undef EXTRA_INFO

#ifndef REG_INVALID
#define REG_INVALID(r) (reg_info[r].width == 0)
#endif

#define DW_CFA_nop                          0x00
#define DW_CFA_set_loc                      0x01
#define DW_CFA_advance_loc1                 0x02
#define DW_CFA_advance_loc2                 0x03
#define DW_CFA_advance_loc4                 0x04
#define DW_CFA_offset_extended              0x05
#define DW_CFA_restore_extended             0x06
#define DW_CFA_undefined                    0x07
#define DW_CFA_same_value                   0x08
#define DW_CFA_register                     0x09
#define DW_CFA_remember_state               0x0a
#define DW_CFA_restore_state                0x0b
#define DW_CFA_def_cfa                      0x0c
#define DW_CFA_def_cfa_register             0x0d
#define DW_CFA_def_cfa_offset               0x0e
#define DW_CFA_def_cfa_expression           0x0f
#define DW_CFA_expression                   0x10
#define DW_CFA_offset_extended_sf           0x11
#define DW_CFA_def_cfa_sf                   0x12
#define DW_CFA_def_cfa_offset_sf            0x13
#define DW_CFA_val_offset                   0x14
#define DW_CFA_val_offset_sf                0x15
#define DW_CFA_val_expression               0x16
#define DW_CFA_lo_user                      0x1c
#define DW_CFA_GNU_window_save              0x2d
#define DW_CFA_GNU_args_size                0x2e
#define DW_CFA_GNU_negative_offset_extended 0x2f
#define DW_CFA_hi_user                      0x3f

#define DW_EH_PE_FORM     0x07
#define DW_EH_PE_native   0x00
#define DW_EH_PE_leb128   0x01
#define DW_EH_PE_data2    0x02
#define DW_EH_PE_data4    0x03
#define DW_EH_PE_data8    0x04
#define DW_EH_PE_signed   0x08
#define DW_EH_PE_ADJUST   0x70
#define DW_EH_PE_abs      0x00
#define DW_EH_PE_pcrel    0x10
#define DW_EH_PE_textrel  0x20
#define DW_EH_PE_datarel  0x30
#define DW_EH_PE_funcrel  0x40
#define DW_EH_PE_aligned  0x50
#define DW_EH_PE_indirect 0x80
#define DW_EH_PE_omit     0xff

#define CIE_ID	0

#define IO_FOPEN_ENTRY 0x63d80
#define IO_FGETS_ENTRY 0x63c70
#define PTHREAD_ONCE_ENTRY 0x85d44

typedef unsigned long uleb128_t;
typedef signed long sleb128_t;

struct eh_frame_hdr_table_entry {
	unsigned long start, fde;
};

typedef enum {
	UNINIT = 0,
	INIT
} table_state;

struct unwind_item {
	enum item_location {
		Nowhere,
		Memory,
		Register,
		Value
	} where;
	uleb128_t value;
};

struct unwind_state {
	uleb128_t loc, org;
	const u8 *cieStart, *cieEnd;
	uleb128_t codeAlign;
	sleb128_t dataAlign;
	struct cfa {
		uleb128_t reg, offs;
	} cfa;
	struct unwind_item regs[ARRAY_SIZE(reg_info)];
	unsigned stackDepth:8;
	unsigned version:8;
	const u8 *label;
	const u8 *stack[MAX_STACK_DEPTH];
};

static const struct cfa badCFA = { ARRAY_SIZE(reg_info), 1 };
static const u32 bad_cie, not_fde;
static const u32 *cie_for_fde(const u32 *fde);
static const u32 *__cie_for_fde(const u32 *fde);
static signed fde_pointer_type(const u32 *cie, unsigned long kern_base,
			       unsigned long user_base);
static unsigned long read_pointer(const u8 **pLoc, const void *end,
				  signed ptrType, unsigned long kern_base,
				  unsigned long user_base);

static unsigned long translate_user_to_kern(unsigned long, unsigned long,
					    unsigned long);
static unsigned long translate_kern_to_user(unsigned long, unsigned long,
					    unsigned long);

static inline unsigned int extract32(unsigned int, int, int);
static inline int sextract32(unsigned int, int, int);

static const table_t *_find_table(const struct hash_table *, unsigned long);
static const table_t *find_table(struct hash_table *, struct unwind_frame_info *);

/* spinlock_t sandbox_unwind_lock; */

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t __kallsyms_lookup_name;

int (*traverse_vma)(unsigned long);
int (*delta_app_inlist)(struct task_struct *);

/** TODO: ztex
 * unwind_add_table() - Add the new unwind table to this list
 * @path: path to the shared object
*/
table_t *unwind_add_table(struct hash_table *phtable, const struct so_info *cur)
{
	table_t *ptable, *root_table = phtable->root_table;
	ptable = kmalloc(sizeof(table_t), GFP_KERNEL);
	if (!ptable) {
		pr_err("[hsuck] fucking axx\n");
		goto err;
	}
	// TODO: ztex
	memset(ptable, 0, sizeof(table_t));
	ptable->info = cur;

	// add the table in the list
	ptable->next = root_table;
	ptable->prev = root_table->prev;
	root_table->prev->next = ptable;
	root_table->prev = ptable;
	return ptable;
err:
	pr_err("[ztex] fail to add table given the path: %s\n", cur->name);
	return NULL;
}
EXPORT_SYMBOL(unwind_add_table);

/**
 * _find_table() - Find the right table given the pc.
 * @pc: the value of the program counter at the time
 *
 * FIXME ztex: now we always return the root table,
 * but we need to find the right table given the pc
 */
static const table_t *_find_table(const struct hash_table *phtable,
			   const unsigned long pc)
{
	int found = 0;
	const table_t *ptable = phtable->root_table;

	if (!ptable)
		return NULL;
	/* FIXME hsuck: need to build an array based on
	 * the range of .text to performe binary search.
	 */
	do {
		unsigned long start, end;
		pr_debug("[hsuck] current table: %s, shared object: %s\n",
			 ptable->name, ptable->info->name);
		start = ptable->info->base_address;
		end = start + ptable->info->pc_range;
		pr_debug("[hsuck] pc range[%#0lx-%#0lx]\n", start, end);
		if (pc >= start && pc < end) {
			found = 1;
			break;
		}
		ptable = ptable->next;
	} while (ptable && ptable != phtable->root_table);

	if (found)
		return ptable;
	else
		return NULL;
}

static const table_t *find_table(struct hash_table *phtable,
			   struct unwind_frame_info *frame)
{
	int retval;
	const table_t *table;

	if (!traverse_vma)
		traverse_vma = (void *)__kallsyms_lookup_name("traverse_vma");

	table = _find_table(phtable, UNW_PC(frame));
	if (!table) {
		do {
			retval = traverse_vma(UNW_PC(frame));
		} while (retval == -EAGAIN);
		phtable->is_inited = 0;
		init_unwind_table(phtable, frame);

		table = _find_table(phtable, UNW_PC(frame));
	}
	return table;
}

static int cmp_eh_frame_hdr_table_entries(const void *p1, const void *p2)
{
	const struct eh_frame_hdr_table_entry *e1 = p1;
	const struct eh_frame_hdr_table_entry *e2 = p2;

	return (e1->start > e2->start) - (e1->start < e2->start);
}

static void swap_eh_frame_hdr_table_entries(void *p1, void *p2, int size)
{
	struct eh_frame_hdr_table_entry *e1 = p1;
	struct eh_frame_hdr_table_entry *e2 = p2;

	swap(e1->start, e2->start);
	swap(e1->fde, e2->fde);
}

static uleb128_t get_uleb128(const u8 **pcur, const u8 *end)
{
	const u8 *cur = *pcur;
	uleb128_t value;
	unsigned int shift;

	for (shift = 0, value = 0; cur < end; shift += 7) {
		if (shift + 7 > 8 * sizeof(value)
			&& (*cur & 0x7fU) >= (1U << (8 * sizeof(value) - shift))) {
			cur = end + 1;
			break;
		}
		value |= (uleb128_t) (*cur & 0x7f) << shift;
		if (!(*cur++ & 0x80))
			break;
	}
	*pcur = cur;

	return value;
}

static sleb128_t get_sleb128(const u8 **pcur, const u8 *end)
{
	const u8 *cur = *pcur;
	sleb128_t value;
	unsigned int shift;

	for (shift = 0, value = 0; cur < end; shift += 7) {
		if (shift + 7 > 8 * sizeof(value)
			&& (*cur & 0x7fU) >= (1U << (8 * sizeof(value) - shift))) {
			cur = end + 1;
			break;
		}
		value |= (sleb128_t) (*cur & 0x7f) << shift;
		if (!(*cur & 0x80)) {
			value |= -(*cur++ & 0x40) << shift;
			break;
		}
	}
	*pcur = cur;

	return value;
}

static const u32 *__cie_for_fde(const u32 *fde)
{
	/*
	CIE Pointer A 4 byte unsigned value that when subtracted from the offset of the current FDE
	yields the offset of the start of the associated CIE. This value shall never be 0.
	*/
   const u32 *cie;

   // See: https://github.com/redox-os/binutils-gdb/blob/master/bfd/elf-eh-frame.c#900
   cie = fde + 1 - fde[1] / sizeof(*fde);

   return cie;
}

static const u32 *cie_for_fde(const u32 *fde)
{
	const u32 *cie;

	if (fde[0] == 0x0 || fde[0] == 0xffffffff) {
		pr_debug("[ztex] the length field value is %x, stop processing\n", fde[0]);
		return &bad_cie;
	}

	// Fixme ztex: here we make an assumption the we don't have extended length field
	if (fde[1] == CIE_ID) {
		return &not_fde;	/* this is a CIE */
	}

	/*
	CIE Pointer: A 4 byte unsigned value that when subtracted from the offset of the current FDE
	yields the offset of the start of the associated CIE. This value shall never be 0.
	*/
	if (fde[1] == 0x0) {
		pr_err("[vicky] failed at [%s]: %d, CIE Pointer is 0\n", __FUNCTION__, __LINE__);
		return NULL;	/* this is not a valid FDE */
	}

	cie = __cie_for_fde(fde);

	if (*cie <= sizeof(*cie) + 4 || *cie >= fde[1] - sizeof(*fde) ||
	    (*cie & (sizeof(*cie) - 1)) || (cie[1] != CIE_ID)) {
		pr_err("[vicky] failed at [%s]: %d, *cie = %u, cie[1] = %u, fde[1] = %u\n",
		       __FUNCTION__, __LINE__, *cie, cie[1], fde[1]);
		return NULL; /* this is not a (valid) CIE */
	}
	return cie;
}

// FIXME ztex: Not sure if this is platform-dependent
// and we probably !!DO NOT!! want to use __get_user
static unsigned long read_pointer(const u8 **pLoc, const void *end,
				  signed ptrType, unsigned long kern_base,
				  unsigned long user_base)
{
	unsigned long value = 0;
	unsigned long offset, upLoc;
	union {
		const u8 *p8;
		const u16 *p16u;
		const s16 *p16s;
		const u32 *p32u;
		const s32 *p32s;
		const unsigned long *pul;
	} ptr;

	if (ptrType < 0 || ptrType == DW_EH_PE_omit)
		return 0;
	ptr.p8 = *pLoc;
	switch (ptrType & DW_EH_PE_FORM) {
	case DW_EH_PE_data2:
		if (end < (const void *)(ptr.p16u + 1))
			return 0;
		if (ptrType & DW_EH_PE_signed)
			value = get_unaligned((u16 *)ptr.p16s++);
		else
			value = get_unaligned((u16 *)ptr.p16u++);
		break;
	case DW_EH_PE_data4:
/* #ifdef CONFIG_64BIT */
		if (end < (const void *)(ptr.p32u + 1))
			return 0;
		if (ptrType & DW_EH_PE_signed)
			value = get_unaligned(ptr.p32s++);
		else
			value = get_unaligned(ptr.p32u++);
		break;
	case DW_EH_PE_data8:
		BUILD_BUG_ON(sizeof(u64) != sizeof(value));
/* #else */
/* 		BUILD_BUG_ON(sizeof(u32) != sizeof(value)); */
/* #endif */
		fallthrough;
	case DW_EH_PE_native:
		if (end < (const void *)(ptr.pul + 1))
			return 0;
		value = get_unaligned((unsigned long *)ptr.pul++);
		break;
	case DW_EH_PE_leb128:
		BUILD_BUG_ON(sizeof(uleb128_t) > sizeof(value));
		value = ptrType & DW_EH_PE_signed ? get_sleb128(&ptr.p8, end) :
						    get_uleb128(&ptr.p8, end);
		if ((const void *)ptr.p8 > end)
			return 0;
		break;
	default:
		return 0;
	}
	switch (ptrType & DW_EH_PE_ADJUST) {
	case DW_EH_PE_abs:
		break;
	case DW_EH_PE_pcrel:
		value += (unsigned long)*pLoc;
		break;
	default:
		return 0;
	}
	if (ptrType & DW_EH_PE_indirect &&
	    (ptrType & DW_EH_PE_ADJUST) == DW_EH_PE_pcrel) {
		/* TODO: translate address space */
#if DEBUG_SANDBOX == 1
		pr_info("[hsuck] value=%#0lx\n", value);
#endif // DEBUG_SANDBOX
		value -= (unsigned long)*pLoc;
		offset = (unsigned long)*pLoc - kern_base;
		upLoc = user_base + offset;
		value += upLoc;
#if DEBUG_SANDBOX == 1
		pr_info("[hsuck] value=%#0lx\n", value);
#endif // DEBUG_SANDBOX
		if (__get_user(value, (unsigned long __user *)value)) {
			pr_err("[hsuck] __get_user() failed\n");
			return 0;
		}
	}
	*pLoc = ptr.p8;

	return value;
}

static signed fde_pointer_type(const u32 *cie, unsigned long kern_base,
			       unsigned long user_base)
{
	const u8 *ptr = (const u8 *)(cie + 2);
	unsigned int version = *ptr;
	uleb128_t codeAlign;
	sleb128_t dataAlign;

	if (*++ptr) {
		const char *aug;
		const u8 *end = (const u8 *)(cie + 1) + *cie;
		uleb128_t len;

		/* check if augmentation size is first (and thus present) */
		if (*ptr != 'z') {
			pr_err("[ztex] the workaround mess up !!! \n");
			return -1;
		}

		/* check if augmentation string is nul-terminated */
		aug = (const void *)ptr;
		ptr = memchr(aug, 0, end - ptr);
		if (ptr == NULL) {
			pr_err("[hsuck] no nul-terminator\n");
			return -1;
		}

		++ptr;		/* skip terminator */
		codeAlign = get_uleb128(&ptr, end);	/* skip code alignment */
		dataAlign = get_sleb128(&ptr, end);	/* skip data alignment */
		/* skip return address column */
		version <= 1 ? (void)++ptr : (void)get_uleb128(&ptr, end);
		len = get_uleb128(&ptr, end); /* augmentation length */

		if (ptr + len < ptr || ptr + len > end)
			return -1;

		end = ptr + len;
		while (*++aug) {
			if (ptr >= end) {
				pr_err("[hsuck] ptr >= end, out of range");
				return -1;
			}
			switch (*aug) {
			case 'L':
				++ptr;
				break;
			case 'P': {
				signed ptrType = *ptr++;

				if (!read_pointer(&ptr, end, ptrType, kern_base,
						  user_base) ||
				    ptr > end) {
#if FIXME_SANDBOX > 0
					pr_err("[hsuck] read_pointer fail or out of range\n");
#endif // FIXME_SANDBOX
					return -1;
				}
			} break;
			case 'R':
				return *ptr;
			default:
				return -1;
			}
		}
	}
	return DW_EH_PE_native | DW_EH_PE_abs;
}

static unsigned long translate_user_to_kern(unsigned long kern_base,
					    unsigned long user_base,
					    unsigned long pc)
{
	unsigned long offset = user_base - pc;
	return kern_base - offset;
}

static unsigned long translate_kern_to_user(unsigned long kern_base,
					    unsigned long user_base,
					    unsigned long kern_pc)
{
	unsigned long offset = kern_base - kern_pc;
	return user_base - offset;
}

static unsigned long extract_insn(unsigned long addr)
{
	int i;
	char buff[4];
	unsigned long insn = 0;

	if (!access_ok((void __user *)addr, 4)) {
		pr_err("[hsuck] permission denied, addr: %lx\n", addr);
		//FIXME: ztex the return type is unsigned
		return -EFAULT;
	}
	if (copy_from_user(buff, (void __user *)addr, 4)) {
		pr_err("[hsuck] fail to copy from user, addr: %lx\n", addr);
		//FIXME: ztex the return type is unsigned
		return -EFAULT;
	}

	for (i = 3; i >= 0; i--)
		insn += (unsigned long)buff[i] << (i * 8);

	return insn;
}

static int is_stp(unsigned long addr)
{
	unsigned long insn;

	if ((insn = extract_insn(addr)) == ((unsigned long)-EFAULT))
		return -1;

	return ((insn & 0xffc00000) == 0xa9000000) ? 1 : 0;
}

static inline unsigned int extract32(unsigned int value, int start, int length)
{
	/* assert(start >= 0 && length > 0 && length <= 32 - start); */
	return (value >> start) & (~0U >> (32 - length));
}

static inline int sextract32(unsigned int value, int start, int length)
{
	/* assert(start >= 0 && length > 0 && length <= 32 - start); */
	return ((int)(value << (32 - length - start))) >> (32 - length);
}

static inline int64_t sextract64(uint64_t value, int start, int length)
{
	/* assert(start >= 0 && length > 0 && length <= 64 - start); */
	/* Note that this implementation relies on right shift of signed
	 * integers being an arithmetic shift.
	 */
	return ((int64_t)(value << (64 - length - start))) >> (64 - length);
}

void deinit_unwind_table(struct hash_table *phtable, int mode)
{
	table_t *tmp, *cur = phtable->root_table;

	if (!cur)
		return;

	do {
		tmp = cur;
		cur = cur->next;
		if (mode == 1)
			RELEASE_MEMORY(tmp->header);
		RELEASE_MEMORY(tmp);
	} while (cur && cur != phtable->root_table);

	return;
}
EXPORT_SYMBOL(deinit_unwind_table);

static void _init_unwind_table(struct hash_table *phtable, struct so_info *cur,
			       struct unwind_frame_info *frame)
{
	const u8 *ptr;
	unsigned int n, hdrSize, found = 0;
	const u32 *fde;
	table_t *table = phtable->root_table;
	unsigned long table_start = (unsigned long)cur->ehframe;
	unsigned long tableSize = cur->eh_frame_size;
	unsigned long user_base = cur->base_address + cur->eh_frame_start;
	struct {
		u8 version;
		u8 eh_frame_ptr_enc;
		u8 fde_count_enc;
		u8 table_enc;
		unsigned long eh_frame_ptr;
		unsigned int fde_count;
		struct eh_frame_hdr_table_entry table[];
	} __attribute__ ((__packed__)) *header;

	pr_debug("[hsuck] %s: kern_addr=%#0lx, size=%#0lx, user_addr=%#0lx\n",
		 cur->name, table_start, tableSize, user_base);

	if (table->info == NULL)
		goto first;

	if(!cur->name || !table->info->name) {
		pr_err("[vicky] current name or table info name is NULL.\n");
		goto ret_err;
	}

	pr_debug("[hsuck] Initializing the table of %s, %d\n", cur->name, phtable->pid);

	do {
		pr_debug("[vicky] table name: %s, cur name:%s\n",
			 table->info->name, cur->name);
		if (strcmp(table->info->name, cur->name) == 0) {
			found = 1;
			break;
		}
		table = table->next;
	} while (table && table != phtable->root_table);

	if (!found) {
		pr_debug("[hsuck] Create new table\n");
		table = unwind_add_table(phtable, cur);
	} else {
		if (table->header && table->hdrsz) {
			pr_debug("[hsuck] %s is inited, hdrsz=%#0lx\n", cur->name, table->hdrsz);
			goto inited;
		}
	}
	pr_debug("[hsuck] %s: %s\n", __FUNCTION__, table->info->name);
	
first:
	table->info = cur;
	table->address = (const void *) table_start;
	table->size = tableSize;

	for (fde = table->address, n = 0;
	     tableSize > sizeof(*fde) && tableSize - sizeof(*fde) >= *fde;
	     tableSize -= sizeof(*fde) + *fde, fde += 1 + *fde / sizeof(*fde)) {
		const u32 *cie = cie_for_fde(fde);
		if (cie == &not_fde)
			continue;
		if (cie == NULL || cie == &bad_cie)
			break;
		// TODO ztex: port fde_pointer_type to check Augmentation String and Augmentation Data
		// TODO ztex: take care of the PC Begin field in FDE
		n++;
	}
	// tableSize should be 4 now, cuz there will be a 4-bytes terminator here
	pr_debug("[ztex] tableSize: %lu, n: %u\n", tableSize, n);
	if (tableSize % 4 != 0 || !n) {
		pr_err("[ztex] The table size or the number of fde is wrong. tableSize: %lu, n: %u\n", tableSize, n);
		goto ret_err;
	}

	// FIXME ztex: this size is related to the size of `header` and the size of `struct eh_frame_hdr_table_entry`
	hdrSize = 4 + sizeof(unsigned long) + sizeof(unsigned int)
		+ n * sizeof(struct eh_frame_hdr_table_entry);
	header = kmalloc(hdrSize, GFP_KERNEL);
	if (!header) {
		pr_err("[ztex] fail to allocate header for size: %u\n", hdrSize);
		goto ret_err;
	}
	// reference: https://refspecs.linuxfoundation.org/LSB_1.3.0/gLSB/gLSB/ehframehdr.html
	header->version = 1; // This value must be 1
	// FIXME ztex: not sure about this part, do not this it is releveant to unwinding
	header->eh_frame_ptr_enc = DW_EH_PE_abs | DW_EH_PE_native;
	header->fde_count_enc = DW_EH_PE_abs | DW_EH_PE_data4;
	header->table_enc = DW_EH_PE_abs | DW_EH_PE_native;
	put_unaligned((unsigned long)table->address, &header->eh_frame_ptr);
	BUILD_BUG_ON(offsetof(typeof(*header), fde_count) %
		     __alignof(typeof(header->fde_count)));
	header->fde_count = n;

	BUILD_BUG_ON(offsetof(typeof(*header), table) %
		     __alignof(typeof(*header->table)));

	for (fde = table->address, tableSize = table->size, n = 0; tableSize;
	     tableSize -= sizeof(*fde) + *fde, fde += 1 + *fde / sizeof(*fde)) {
		signed ptrType; 
		const u32 *cie = cie_for_fde(fde);

		if (cie == &not_fde)
			continue;	/* this is a CIE */

		if (cie == NULL || cie == &bad_cie)
			break;
		/*
		PC Begin: An encoded constant that indicates the address of the initial location
		associated with this FDE.
		*/
		ptr = (const u8 *)(fde + 2);
		ptrType = fde_pointer_type(cie, table_start, user_base);
		if (ptrType == -1) {
#if FIXME_SANDBOX > 0
			pr_err("[hsuck] pointer type error, FDE: %#0lx\n", (unsigned long)fde);
#endif // FIXME_SANDBOX
		}
		header->table[n].start =
			read_pointer(&ptr, (const u8 *)(fde + 1) + *fde,
				     ptrType, table_start, user_base);
		header->table[n].fde = (unsigned long)fde;
		++n;
	}
	WARN_ON(n != header->fde_count);

	sort(header->table, n, sizeof(*header->table),
	     cmp_eh_frame_hdr_table_entries, swap_eh_frame_hdr_table_entries);
	table->hdrsz = hdrSize;
	smp_wmb();
	table->header = (const void *)header;
	get_task_comm(table->name, frame->task);
	pr_debug("[ztex] parsing .eh_frame sucessful\n");
inited:
	return;
ret_err:
	pr_err("[ztex] failed to process .eh_frame\n");
}

void init_unwind_table(struct hash_table *phtable,
		       struct unwind_frame_info *frame)
{
	int bkt;
	struct so_info *cur;

	if (!phtable || hash_empty(phtable->htable)) {
		pr_err("[hsuck] %s, L%d: hash table not found or no entries\n",
			 __FUNCTION__, __LINE__);
		return;
	}
	pr_debug("[hsuck] %s, L%d: %s, inited=%d\n", __FUNCTION__, __LINE__,
		 phtable->name, phtable->is_inited);
	if (phtable->is_inited)
		return;

	hash_for_each (phtable->htable, bkt, cur, node) {
		_init_unwind_table(phtable, cur, frame);
	}

	phtable->is_inited = 1;
	return;
}
EXPORT_SYMBOL(init_unwind_table);

static int advance_loc(unsigned long delta, struct unwind_state *state)
{
	state->loc += delta * state->codeAlign;

	/* FIXME_Rajesh: Probably we are defining for the initial range as well;
	   return delta > 0;
	 */
	pr_debug(KERN_CONT "delta %3lu => loc 0x%lx: ", delta, state->loc);
	return 1;
}

static void set_rule(uleb128_t reg, enum item_location where, uleb128_t value,
			 struct unwind_state *state)
{
	if (reg < ARRAY_SIZE(state->regs)) {
		state->regs[reg].where = where;
		state->regs[reg].value = value;

		pr_debug(KERN_CONT "r%lu: ", reg);
		switch (where) {
		case Nowhere:
			pr_debug(KERN_CONT "s ");
			break;
		case Memory:
			pr_debug(KERN_CONT "c(%ld) ", value * state->dataAlign);
			break;
		case Register:
			pr_debug(KERN_CONT "r(%lu) ", value);
			break;
		case Value:
			pr_debug(KERN_CONT "v(%lu) ", value);
			break;
		default:
			break;
		}
	}
}

static int processCFI(const u8 *start, const u8 *end, unsigned long targetLoc,
		      signed ptrType, struct unwind_state *state,
		      unsigned long kern_base, unsigned long user_base)
{
	union {
		const u8 *p8;
		const u16 *p16;
		const u32 *p32;
	} ptr;
	int result = 1;
	u8 opcode;

	if (start != state->cieStart) {
		state->loc = state->org;
		result = processCFI(state->cieStart, state->cieEnd, 0, ptrType,
				    state, kern_base, user_base);
		if (targetLoc == 0 && state->label == NULL)
			return result;
	}
	/* reference: https://blog.csdn.net/pwl999/article/details/107569603#23_Instructions_Opcode_618 */
	for (ptr.p8 = start; result && ptr.p8 < end;) {
		switch (*ptr.p8 >> 6) {
			uleb128_t value;

		case 0:
			opcode = *ptr.p8++;

			switch (opcode) {
			case DW_CFA_nop:
				pr_debug(KERN_CONT "DW_CFA_nop ");
				break;
			case DW_CFA_set_loc:
				state->loc = read_pointer(&ptr.p8, end, ptrType,
							  kern_base, user_base);
				if (state->loc == 0)
					result = 0;
				pr_debug(KERN_CONT "DW_CFA_set_loc: 0x%lx ", state->loc);
				break;
			case DW_CFA_advance_loc1:
				pr_debug(KERN_CONT "\nDW_CFA_advance_loc1: ");
				result = ptr.p8 < end
					&& advance_loc(*ptr.p8++, state);
				break;
			case DW_CFA_advance_loc2:
				pr_debug(KERN_CONT "\nDW_CFA_advance_loc2: ");
				value = *ptr.p8++;
				value += *ptr.p8++ << 8;
				result = ptr.p8 <= end + 2
					/* && advance_loc(*ptr.p16++, state); */
					&& advance_loc(value, state);
				break;
			case DW_CFA_advance_loc4:
				pr_debug(KERN_CONT "\nDW_CFA_advance_loc4: ");
				result = ptr.p8 <= end + 4
					&& advance_loc(*ptr.p32++, state);
				break;
			case DW_CFA_offset_extended:
				pr_debug(KERN_CONT "DW_CFA_offset_extended: ");
				value = get_uleb128(&ptr.p8, end);
				set_rule(value, Memory,
					 get_uleb128(&ptr.p8, end), state);
				break;
			case DW_CFA_val_offset:
				pr_debug(KERN_CONT "DW_CFA_val_offset: ");
				value = get_uleb128(&ptr.p8, end);
				set_rule(value, Value,
					 get_uleb128(&ptr.p8, end), state);
				break;
			case DW_CFA_offset_extended_sf:
				pr_debug(KERN_CONT "DW_CFA_offset_extended_sf: ");
				value = get_uleb128(&ptr.p8, end);
				set_rule(value, Memory,
					 get_sleb128(&ptr.p8, end), state);
				break;
			case DW_CFA_val_offset_sf:
				pr_debug(KERN_CONT "DW_CFA_val_offset_sf: ");
				value = get_uleb128(&ptr.p8, end);
				set_rule(value, Value,
					 get_sleb128(&ptr.p8, end), state);
				break;
			case DW_CFA_restore_extended:
				pr_debug(KERN_CONT "DW_CFA_restore_extended: ");
				break;
			case DW_CFA_undefined:
				value = get_uleb128(&ptr.p8, end);
				pr_debug(KERN_CONT "DW_CFA_undefined: %lu", value);
				break;
			case DW_CFA_same_value:
				pr_debug(KERN_CONT "DW_CFA_same_value: ");
				set_rule(get_uleb128(&ptr.p8, end), Nowhere, 0,
					 state);
				break;
			case DW_CFA_register:
				pr_debug(KERN_CONT "DW_CFA_register: ");
				value = get_uleb128(&ptr.p8, end);
				set_rule(value,
					 Register,
					 get_uleb128(&ptr.p8, end), state);
				break;
			case DW_CFA_remember_state:
				pr_debug(KERN_CONT "DW_CFA_remember_state: ");
				if (ptr.p8 == state->label) {
					state->label = NULL;
					return 1;
				}
				if (state->stackDepth >= MAX_STACK_DEPTH)
					return 0;
				state->stack[state->stackDepth++] = ptr.p8;
				break;
			case DW_CFA_restore_state:
				pr_debug(KERN_CONT "DW_CFA_restore_state: ");
				if (state->stackDepth) {
					const uleb128_t loc = state->loc;
					const u8 *label = state->label;

					state->label =
						state->stack[state->stackDepth - 1];
					memcpy(&state->cfa, &badCFA,
						   sizeof(state->cfa));
					memset(state->regs, 0,
						   sizeof(state->regs));
					state->stackDepth = 0;
					result = processCFI(start, end, 0,
							    ptrType, state,
							    kern_base,
							    user_base);
					state->loc = loc;
					state->label = label;
				} else
					return 0;
				break;
			case DW_CFA_def_cfa:
				state->cfa.reg = get_uleb128(&ptr.p8, end);
				pr_debug(KERN_CONT "DW_CFA_def_cfa: r%lu ", state->cfa.reg);
				fallthrough;
			case DW_CFA_def_cfa_offset:
				state->cfa.offs = get_uleb128(&ptr.p8, end);
				pr_debug(KERN_CONT "DW_CFA_def_cfa_offset: %lu ",
					  state->cfa.offs);
				break;
			case DW_CFA_def_cfa_sf:
				state->cfa.reg = get_uleb128(&ptr.p8, end);
				fallthrough;
			case DW_CFA_def_cfa_offset_sf:
				state->cfa.offs = get_sleb128(&ptr.p8, end)
					* state->dataAlign;
				break;
			case DW_CFA_def_cfa_register:
				pr_debug(KERN_CONT "DW_CFA_def_cfa_register: ");
				state->cfa.reg = get_uleb128(&ptr.p8, end);
				break;
				/*todo case DW_CFA_def_cfa_expression: */
				/*todo case DW_CFA_expression: */
				/*todo case DW_CFA_val_expression: */
			case DW_CFA_GNU_args_size:
				get_uleb128(&ptr.p8, end);
				break;
			case DW_CFA_GNU_negative_offset_extended:
				value = get_uleb128(&ptr.p8, end);
				set_rule(value, Memory,
					 (uleb128_t)0 -
						 get_uleb128(&ptr.p8, end),
					 state);
				break;
			case DW_CFA_GNU_window_save:
			default:
				pr_debug(KERN_CONT "UNKNOWN OPCODE 0x%x\n", opcode);
				result = 0;
				break;
			}
			break;
		case 1:
			pr_debug(KERN_CONT "\nDW_CFA_advance_loc: ");
			result = advance_loc(*ptr.p8++ & 0x3f, state);
			break;
		case 2:
			pr_debug(KERN_CONT "DW_CFA_offset: ");
			value = *ptr.p8++ & 0x3f;
			set_rule(value, Memory, get_uleb128(&ptr.p8, end),
				 state);
			break;
		case 3:
			pr_debug(KERN_CONT "DW_CFA_restore: ");
			set_rule(*ptr.p8++ & 0x3f, Nowhere, 0, state);
			break;
		}

		if (ptr.p8 > end) {
			pr_debug("[hsuck] ptr out of range");
			result = 0;
		}
		if (result && targetLoc != 0) {
			if (targetLoc >= state->loc)
				result = 1;
			else
				return result;
		}
	}

	return result && ptr.p8 == end && (targetLoc == 0 || (
		/*todo While in theory this should apply, gcc in practice omits
		  everything past the function prolog, and hence the location
		  never reaches the end of the function.
		targetLoc < state->loc && */  state->label == NULL));
}

int delta_unwind(struct hash_table *phtable, struct unwind_frame_info *frame)
{
#define FRAME_REG(r, t) (((t *)frame)[reg_info[r].offs])
	const u32 *fde = NULL, *cie = NULL;
	const u8 *ptr = NULL, *end = NULL;
	const u8 *hdr = NULL;
	unsigned long pc = UNW_PC(frame) - frame->call_frame;
	unsigned long pc_kern = 0;
	unsigned long startLoc = 0, endLoc = 0, cfa;
	unsigned long tableSize;
	unsigned int i, fde_count;
	signed ptrType = -1;
	uleb128_t retAddrReg = 0;
	const table_t  *table;
	struct unwind_state state;
	unsigned long *fptr;
	unsigned long temp = 0;
	struct eh_frame_hdr_table_entry *temp_ptr;
	unsigned long bs_mid, bs_l, bs_r;
	unsigned long kern_base, user_base, addr;

	pr_debug("[hsuck] %s, pc: %lx, sp: %lx\n", __FUNCTION__, UNW_PC(frame),
		 UNW_SP(frame));

	if (UNW_PC(frame) == 0) {
		pr_err("[vicky] failed at [%s]: %d\n", __FUNCTION__, __LINE__);
		return -EINVAL;
	}

	table = find_table(phtable, frame);
	if (!table) {
		pr_err("[ztex] %s:%d fail to find the corresponding table, pc: %lx\n",
		       __FUNCTION__, __LINE__, UNW_PC(frame));
		return -EFAULT;
	}

	frame->base_addr = table->info->base_address;
	kern_base = (unsigned long)table->info->ehframe;
	user_base = table->info->base_address + table->info->eh_frame_start;
	pc_kern = translate_user_to_kern(kern_base, user_base, pc);
	pr_debug("[hsuck] After translating, pc: %lx\n", pc_kern);
	pr_debug("[hsuck] table name: %s, user base: %#0lx, kern base:%#0lx\n",
		 table->info->name, user_base, kern_base);

	hdr = table->header;
	if (table == NULL || hdr == NULL || hdr[0] != 1) {
		pr_err("[vicky] failed at [%s]: %d\n", __FUNCTION__, __LINE__);
		return -EINVAL;
	}
	
	smp_rmb();
	switch (hdr[3] & DW_EH_PE_FORM) {
	case DW_EH_PE_native:
		tableSize = sizeof(unsigned long);
		break;
	case DW_EH_PE_data2:
		tableSize = 2;
		break;
	case DW_EH_PE_data4:
		tableSize = 4;
		break;
	case DW_EH_PE_data8:
		tableSize = 8;
		break;
	default:
		tableSize = 0;
		break;
	}

	ptr = hdr + 4;
	end = hdr + table->hdrsz;

	if (tableSize == 0 ||
	    read_pointer(&ptr, end, hdr[1], kern_base, user_base) !=
		    (unsigned long)table->address ||
	    (fde_count = read_pointer(&ptr, end, hdr[2], kern_base,
				      user_base)) <= 0 ||
	    fde_count != (end - ptr) / (2 * tableSize) ||
	    ((end - ptr) % (2 * tableSize))) {
		pr_err("[vicky] failed at [%s]: %d\n", __FUNCTION__, __LINE__);
		return -EINVAL;
	}
	pr_debug("[hsuck] table name=%s, nFDE=%u\n", table->info->name,
		fde_count);

	temp_ptr = (struct eh_frame_hdr_table_entry *)ptr;
#if DEBUG_SANDBOX == 2
	for (int i = 0; i < fde_count; i++) {
		if (i % 100 == 0) {
			pr_debug("[vicky] (user) %d: startLoc = %lx, fde = %lx\n",
				 i,
				 translate_kern_to_user(kern_base, user_base,
						        temp_ptr[i].start),
				 translate_kern_to_user(kern_base, user_base,
						        temp_ptr[i].fde));
			pr_debug("[vicky] (kern) %d: startLoc = %lx, fde = %lx\n",
				 i, temp_ptr[i].start, temp_ptr[i].fde);
		}
	}
#endif //DEBUG_SANDBOX
	bs_l = 0, bs_r = fde_count - 1;
	while (bs_l <= bs_r) {
		bs_mid = (bs_l + bs_r) / 2;
		if (temp_ptr[bs_mid].start < pc_kern) {
			bs_l = bs_mid + 1;
		} else if (temp_ptr[bs_mid].start > pc_kern) {
			bs_r = bs_mid - 1;
		} else {
			bs_r = bs_mid;
			break;
		}
	}
	if (bs_r < 0) {
		pr_err("[vicky] binary search failed.\n");
		return -EINVAL;
	}
	startLoc = temp_ptr[bs_r].start;
	fde = (const u32 *)temp_ptr[bs_r].fde;
	pr_debug("[vicky] binSearch found startLoc = %lx, fde = %lx\n",
		 translate_kern_to_user(kern_base, user_base, startLoc),
		 translate_kern_to_user(kern_base, user_base,
					(const unsigned long)fde));

	//startLoc = FDE pc begin
	//fde = fde addr
	if (fde != NULL) {
		cie = cie_for_fde(fde);
		ptr = (const u8 *)(fde + 2);
		if (cie == NULL || cie == &bad_cie || cie == &not_fde) {
			pr_err("[vicky] failed at [%s]: %d, cie is %px\n",
			       __FUNCTION__, __LINE__, cie);
		} else if ((ptrType = fde_pointer_type(cie, kern_base,
						       user_base)) < 0) {
			pr_err("[vicky] failed at [%s]: %d, ptrType = %d\n",
			       __FUNCTION__, __LINE__, ptrType);
		} else if ((temp = read_pointer(
				    &ptr, (const u8 *)(fde + 1) + *fde, ptrType,
				    kern_base, user_base)) != startLoc) {
			pr_err("[vicky] failed at [%s]: %d, "
			       "error startLoc = %lx, correct startLoc = %lx\n",
			       __FUNCTION__, __LINE__, temp, startLoc);
		} else {
			if (!(ptrType & DW_EH_PE_indirect))
				ptrType &= DW_EH_PE_FORM | DW_EH_PE_signed;
			endLoc = startLoc +
				 read_pointer(&ptr,
					      (const u8 *)(fde + 1) + *fde,
					      ptrType, kern_base, user_base);
			if (pc_kern >= endLoc || pc_kern < startLoc) {
				pr_err("[vicky] failed at [%s]: %d, "
				       "startLoc = %lx, pc_kern = %lx, endLoc = %lx, "
				       "base = %lx, main() = %lx\n",
				       __FUNCTION__, __LINE__, startLoc,
				       pc_kern, endLoc, kern_base,
				       phtable->elf_entry);
				fde = NULL;
				cie = NULL;
			}
		}
	}

	frame->entry_point =
		translate_kern_to_user(kern_base, user_base, startLoc);
	/* frame->entry_end = translate_kern_to_user(kern_base, user_base, endLoc); */
	/* We have reached main or clone */
	if (startLoc ==
	    translate_user_to_kern(kern_base, user_base, phtable->elf_entry))
		return 1;
	else if (startLoc == translate_user_to_kern(kern_base, user_base,
						    phtable->clone_entry))
		return 2;

	if (cie != NULL) {
		memset(&state, 0, sizeof(state));
		state.cieEnd = ptr;	/* keep here temporarily */
		ptr = (const u8 *)(cie + 2);
		end = (const u8 *)(cie + 1) + *cie;
		frame->call_frame = 1;
		/* check if augmentation size is first (thus present) */
		if (*++ptr && *ptr == 'z') {
			while (++ptr < end && *ptr) {
				switch (*ptr) {
				/* chk for ignorable or already handled
					* nul-terminated augmentation string */
				case 'L':
				case 'P':
				case 'R':
					continue;
				case 'S':
					frame->call_frame = 0;
					continue;
				default:
					break;
				}
				break;
			}
			if (ptr >= end || *ptr){
				pr_err("[vicky] failed at [%s]: %d, cie is NULL\n",
				       __FUNCTION__, __LINE__);
				cie = NULL;
			}
		}
		++ptr;
	}
	else{
		pr_err("[vicky] failed at [%s]: %d, cie is NULL\n",
		       __FUNCTION__, __LINE__);
	}

	if (cie != NULL) {
		/* get code alignment factor */
		state.codeAlign = get_uleb128(&ptr, end);
		/* get data alignment factor */
		state.dataAlign = get_sleb128(&ptr, end);
		if (state.codeAlign == 0 || state.dataAlign == 0 || ptr >= end){
			pr_err("[vicky] failed at [%s]: %d, cie is NULL\n",
			       __FUNCTION__, __LINE__);
			cie = NULL;
		}
		else {
			retAddrReg = state.version <= 1 ?
					     *ptr++ :
					     get_uleb128(&ptr, end);
			pr_debug("[hsuck] CIE Frame Info:\n");
			pr_debug("[hsuck] return Address register 0x%lx\n", retAddrReg);
			pr_debug("[hsuck] data Align: %ld\n", state.dataAlign);
			pr_debug("[hsuck] code Align: %lu\n", state.codeAlign);
			/* skip augmentation */
			if (((const char *)(cie + 2))[1] == 'z') {
				uleb128_t augSize = get_uleb128(&ptr, end);
				ptr += augSize;
			}
			if (ptr > end || retAddrReg >= ARRAY_SIZE(reg_info) ||
			    REG_INVALID(retAddrReg) ||
			    reg_info[retAddrReg].width !=
				    sizeof(unsigned long)) {
				pr_err("[vicky] failed at [%s]: %d, cie is NULL\n",
				       __FUNCTION__, __LINE__);
				cie = NULL;
			}
		}
	} else {
		pr_err("[vicky] failed at [%s]: %d, cie is NULL\n",
		       __FUNCTION__, __LINE__);
	}

	if (cie != NULL) {
		state.cieStart = ptr;
		ptr = state.cieEnd;
		state.cieEnd = end;
		end = (const u8 *)(fde + 1) + *fde;
		/* skip augmentation */
		if (((const char *)(cie + 2))[1] == 'z') {
			uleb128_t augSize = get_uleb128(&ptr, end);
			if ((ptr += augSize) > end)
				fde = NULL;
		}
	}

	if (cie == NULL) {
		pr_err("[vicky] failed at [%s]: %d, cie is NULL\n",
		       __FUNCTION__, __LINE__);
		return -EINVAL;
	}

	if (fde == NULL) {
		pr_err("[vicky] failed at [%s]: %d, fde is NULL\n",
		       __FUNCTION__, __LINE__);
		return -EINVAL;
	}
	state.org = startLoc;
	memcpy(&state.cfa, &badCFA, sizeof(state.cfa));

	/* process instructions
	 * For ARC, we optimize by having blink(retAddrReg) with
	 * the sameValue in the leaf function, so we should not check
	 * state.regs[retAddrReg].where == Nowhere
	 */
	pr_debug("[hsuck] Processing CFI\n");
	if (!processCFI(ptr, end, pc_kern, ptrType, &state, kern_base,
			user_base) ||
	    state.loc > endLoc ||
	    /* state.regs[retAddrReg].where == Nowhere || */
	    state.cfa.reg >= ARRAY_SIZE(reg_info) ||
	    reg_info[state.cfa.reg].width != sizeof(unsigned long) ||
	    state.cfa.offs % sizeof(unsigned long)) {
		pr_err("[vicky] failed at [%s]: %d\n", __FUNCTION__, __LINE__);
		return -EIO;
	}

#if DEBUG_SANDBOX == 1
	pr_debug("[hsuck] Register state based on the rules parsed from FDE:\n");
	for (i = 0; i < ARRAY_SIZE(state.regs); ++i) {
		if (REG_INVALID(i))
			continue;

		switch (state.regs[i].where) {
		case Nowhere:
			break;
		case Memory:
			pr_debug(" x%d: c(%ld),", i,
				state.regs[i].value * state.dataAlign);
			break;
		case Register:
			pr_debug(" x%d: r(%ld),", i, state.regs[i].value);
			break;
		case Value:
			pr_debug(" x%d: v(%ld),", i, state.regs[i].value);
			break;
		}
	}
#endif

	if (frame->call_frame &&
	    !UNW_DEFAULT_RA(state.regs[retAddrReg], state.dataAlign))
		frame->call_frame = 0;

	cfa = FRAME_REG(state.cfa.reg, unsigned long) + state.cfa.offs;
	startLoc = min_t(unsigned long, UNW_SP(frame), cfa);
	endLoc = max_t(unsigned long, UNW_SP(frame), cfa);
	pr_debug("[vicky] cfa:%lx; startLoc:%lx; endLoc:%lx\n", cfa, startLoc,
		 endLoc);
	/* we are not sure why we need to do the following adjustment
	if (STACK_LIMIT(startLoc) != STACK_LIMIT(endLoc)) {
		startLoc = min(STACK_LIMIT(cfa), cfa);
		endLoc = max(STACK_LIMIT(cfa), cfa);
	}
	*/

	pr_debug("[hsuck] CFA reg: %lx, offset: %lx => %lx\n", state.cfa.reg,
		 state.cfa.offs, cfa);

	for (i = 0; i < ARRAY_SIZE(state.regs); ++i) {
		if (REG_INVALID(i)) {
			if (state.regs[i].where == Nowhere)
				continue;
			pr_err("[vicky] failed at [%s]: %d\n", __FUNCTION__,
			       __LINE__);
			return -EIO;
		}

		switch (state.regs[i].where) {
		default:
			break;
		case Register:
			if (state.regs[i].value >= ARRAY_SIZE(reg_info) ||
			    	REG_INVALID(state.regs[i].value) ||
			    	reg_info[i].width >
					reg_info[state.regs[i].value].width) {
				pr_err("[vicky] failed at [%s]: %d\n",
				       __FUNCTION__, __LINE__);
				return -EIO;
			}

			switch (reg_info[state.regs[i].value].width) {
			case sizeof(u8):
				state.regs[i].value = FRAME_REG(
					state.regs[i].value, const u8);
				break;
			case sizeof(u16):
				state.regs[i].value = FRAME_REG(
					state.regs[i].value, const u16);
				break;
			case sizeof(u32):
				state.regs[i].value = FRAME_REG(
					state.regs[i].value, const u32);
				break;
/* #ifdef CONFIG_64BIT */
			case sizeof(u64):
				state.regs[i].value = FRAME_REG(
					state.regs[i].value, const u64);
				break;
/* #endif */
			default:
				pr_err("[vicky] failed at [%s]: %d\n",
				       __FUNCTION__, __LINE__);
				return -EIO;
			}
			break;
		}
	}

	pr_debug("[hsuck] Register state after evaluation with realtime Stack:\n");
	fptr = (unsigned long *)(&frame->regs);
	for (i = 0; i < ARRAY_SIZE(state.regs); ++i, fptr++) {
		if (REG_INVALID(i))
			continue;
		switch (state.regs[i].where) {
		case Nowhere:
			if (reg_info[i].width != sizeof(UNW_SP(frame)) ||
			    &FRAME_REG(i, __typeof__(UNW_SP(frame))) !=
				    &UNW_SP(frame))
				continue;
			UNW_SP(frame) = cfa;
			break;
		case Register:
			switch (reg_info[i].width) {
			case sizeof(u8):
				FRAME_REG(i, u8) = state.regs[i].value;
				break;
			case sizeof(u16):
				FRAME_REG(i, u16) = state.regs[i].value;
				break;
			case sizeof(u32):
				FRAME_REG(i, u32) = state.regs[i].value;
				break;
			case sizeof(u64):
				FRAME_REG(i, u64) = state.regs[i].value;
				break;
			default:
				pr_err("[vicky] failed at [%s]: %d\n",
				       __FUNCTION__, __LINE__);
				return -EIO;
			}
			break;
		case Value:
			if (reg_info[i].width != sizeof(unsigned long)) {
				pr_err("[vicky] failed at [%s]: %d\n",
				       __FUNCTION__, __LINE__);
				return -EIO;
			}
			FRAME_REG(i, unsigned long) =
				cfa + state.regs[i].value * state.dataAlign;
			break;
		case Memory:
			addr = cfa + state.regs[i].value * state.dataAlign;

			if ((state.regs[i].value * state.dataAlign) %
				    sizeof(unsigned long) ||
			    addr < startLoc ||
			    addr + sizeof(unsigned long) < addr ||
			    addr + sizeof(unsigned long) > endLoc) {
				pr_err("[vicky] failed at [%s]: %d. i = %u, value = %lu,\
					dataAlign = %ld, addr = %lx, startLoc = %lx,\
					endLoc = %lx\n",
				       __FUNCTION__, __LINE__, i,
				       state.regs[i].value, state.dataAlign,
				       addr, startLoc, endLoc);
				return -EIO;
			}

			switch (reg_info[i].width) {
			case sizeof(u8):
				__get_user(FRAME_REG(i, u8), (u8 __user *)addr);
				break;
			case sizeof(u16):
				__get_user(FRAME_REG(i, u16),
					   (u16 __user *)addr);
				break;
			case sizeof(u32):
				__get_user(FRAME_REG(i, u32),
					   (u32 __user *)addr);
				break;
			case sizeof(u64):
				__get_user(FRAME_REG(i, u64),
					   (u64 __user *)addr);
				break;
			default:
				pr_err("[vicky] failed at [%s]: %d\n",
				       __FUNCTION__, __LINE__);
				return -EIO;
			}
			break;
		}
		pr_debug("x%d: 0x%lx ", i, *fptr);
	}
	UNW_PC(frame) = frame->regs.x30;
	return 0;
#undef FRAME_REG
}

/* Unconditional branch (immediate)
 *   31  30	  26 25				         0
 * +----+-----------+-------------------------------------+
 * | op | 0 0 1 0 1 |                 imm26               |
 * +----+-----------+-------------------------------------+
 */
static unsigned long disas_uncond_b_imm(unsigned long addr, unsigned int insn)
{
	pr_debug("[hsuck] %s: addr=%#0lx, call target=%#0lx\n", __FUNCTION__,
		 addr, addr + sextract32(insn, 0, 26) * 4);
	return addr + sextract32(insn, 0, 26) * 4;
}

/* Unconditional branch (register)
 *  31		 25 24   21 20   16 15   10 9	 5 4	 0
 * +---------------+-------+-------+-------+------+-------+
 * | 1 1 0 1 0 1 1 |  opc  |  op2  |  op3  |  Rn  |  op4  |
 * +---------------+-------+-------+-------+------+-------+
 */
/* static unsigned int disas_uncond_b_reg(unsigned long addr, unsigned int insn) */
/* { */
/* 	pr_debug("[hsuck] %s: addr=%#0lx, call target(reg)=%#0x\n", */
/* 		__FUNCTION__, addr, extract32(insn, 5, 5)); */
/* 	return extract32(insn, 5, 5); */
/* } */

static unsigned long disas_b_insns(const struct unwind_frame_info *frame,
				   unsigned long addr, unsigned int insn)
{
	/* unsigned int reg; */
	unsigned long retval;

	switch (extract32(insn, 25, 7)) {
	case 0x0a: case 0x0b:
	case 0x4a: case 0x4b:
		retval = disas_uncond_b_imm(addr, insn);
		if (insn & (1U << 31))
			pr_debug("[hsuck] bl insn\n");
		else
			pr_debug("[hsuck] b insn\n");
		break;
	case 0x6b:
		/* reg = disas_uncond_b_reg(addr, insn); */
		/* retval = ((const unsigned long *)(&(frame->regs.x0)))[reg]; */
		retval = -1;
		switch (extract32(insn, 21, 4)) {
		case 0: /* BR */
			pr_debug("[hsuck] %s: br insn\n", __FUNCTION__);
			break;
		case 1: /* BLR */
			pr_debug("[hsuck] %s: blr insn\n", __FUNCTION__);
			break;
		case 8: /* BRAA */
			pr_debug("[hsuck] %s: braa insn\n", __FUNCTION__);
			break;
		case 9: /* BLRAA */
			pr_debug("[hsuck] %s: blraa insn\n", __FUNCTION__);
			break;
		default:
			pr_debug("[hsuck] other type\n");
			break;
		}
		break;
	default:
		retval = 0;
		break;
	}

	return retval;
}

/* PC-rel. addressing
 *   31  30   29 28       24 23                5 4    0
 * +----+-------+-----------+-------------------+------+
 * | op | immlo | 1 0 0 0 0 |       immhi       |  Rd  |
 * +----+-------+-----------+-------------------+------+
 */
static unsigned long disas_pc_rel_adr(unsigned long addr, unsigned int insn)
{
	unsigned int page;
	unsigned long offset;

	page = extract32(insn, 31, 1);
	/* SignExtend(immhi:immlo) -> offset */
	offset = sextract64(insn, 5, 19);
	offset = offset << 2 | extract32(insn, 29, 2);
	if (page) {
		/* ADRP (page based) */
		addr &= ~0xfff;
		offset <<= 12;
	}

	addr += offset;
	pr_debug("[hsuck] base=%#0lx\n", addr);

	return addr;
}

static unsigned long disas_data_proc_imm(unsigned long addr, unsigned int insn)
{
	unsigned long retval;

	switch (extract32(insn, 23, 6)) {
	case 0x20: case 0x21:
		retval = disas_pc_rel_adr(addr, insn);
		break;
	default:
		retval = 0;
		break;
	}

	return retval;
}

/*
 * Load/store (unsigned immediate)
 *
 * 31 30 29   27  26 25 24 23 22 21        10 9     5
 * +----+-------+---+-----+-----+------------+-------+------+
 * |size| 1 1 1 | V | 0 1 | opc |   imm12    |  Rn   |  Rt  |
 * +----+-------+---+-----+-----+------------+-------+------+
 */
static unsigned long disas_ldst_reg(unsigned long addr, unsigned int insn)
{
	/* bool is_vector = extract32(insn, 26, 1); */
	/* int opc = extract32(insn, 0, 5); */
	/* int size = extract32(insn, 30, 2); */
	/* unsigned int imm12 = extract32(insn, 10, 12); */
	return (unsigned int)extract32(insn, 10, 12)
	       << (int)extract32(insn, 30, 2);
}

static unsigned long disas_ldst(unsigned long addr, unsigned int insn)
{
	unsigned long retval;
	switch (extract32(insn, 24, 6)) {
	case 0x38: case 0x39:
	case 0x3c: case 0x3d:
		retval = disas_ldst_reg(addr, insn);
		break;
	default:
		retval = 0;
		break;
	}

	return retval;
}

static unsigned long extract_target_from_plt(unsigned long addr)
{
	unsigned long retval = 0, base, offset;
	unsigned int insn, insn_type;

	insn = extract_insn(addr);
	if (insn == (unsigned long)-EFAULT)
		goto out;

	insn_type = extract32(insn, 25, 4);
	pr_debug("[hsuck] %#0lx: insn=%#0x, type=%#0x\n", addr, insn,
		 insn_type);

	if (insn_type == 0x8 || insn_type == 0x9)
		base = disas_data_proc_imm(addr, insn);
	else
		goto out;

	addr += 4;
	insn = extract_insn(addr);
	if (insn == (unsigned long)-EFAULT)
		goto out;

	insn_type = extract32(insn, 25, 4);
	pr_debug("[hsuck] %#0lx: insn=%#0x, type=%#0x\n", addr, insn,
		 insn_type);

	if (insn_type == 0x4 || insn_type == 0x6 || insn_type == 0xc ||
	    insn_type == 0xe)
		offset = disas_ldst(addr, insn);
	else
		goto out;

	if (__get_user(retval, (unsigned long __user *)(base + offset)))
		pr_err("[hsuck] %s:%d __get_user() failed\n", __FUNCTION__,
		       __LINE__);
	pr_debug("[hsuck] real call target=%#0lx\n", retval);

out:
	return retval;
}

/**
 * find_all_branches() - check whether one of branch can reach entry point
 * phtable:     hash table of the process
 * frame:       current context
 * entry_point: the entry point of the function where PC at
 */
static int find_all_branches(struct hash_table *phtable,
			     struct unwind_frame_info *frame,
			     unsigned long entry_point,
			     unsigned short depth)
{
	const u32 *fde = NULL, *cie = NULL;
	const u8 *ptr = NULL, *end = NULL, *hdr = NULL;
	const table_t *table;
	unsigned int fde_count;
	unsigned int insn, insn_type;
	unsigned long addr, b_target;
	unsigned long retval;
	unsigned long pc = UNW_PC(frame) - frame->call_frame;
	unsigned long startLoc = 0, endLoc = 0;
	unsigned long tableSize;
	unsigned long temp = 0;
	unsigned long bs_mid, bs_l, bs_r;
	unsigned long kern_base, user_base, pc_kern = 0;
	signed ptrType = -1;
	struct eh_frame_hdr_table_entry *temp_ptr;

	if (!depth)
		return -EINVAL;

	table = find_table(phtable, frame);
	if (!table) {
		pr_err("[ztex] %s:%d fail to find the corresponding table, pc: %#0lx\n",
		       __FUNCTION__, __LINE__, UNW_PC(frame));
		return -EFAULT;
	}

	kern_base = (unsigned long)table->info->ehframe;
	user_base = table->info->base_address + table->info->eh_frame_start;
	pc_kern = translate_user_to_kern(kern_base, user_base, pc);
	pr_debug("[hsuck] After translating, pc: %lx\n", pc_kern);

	hdr = table->header;
	if (!hdr || hdr[0] != 1) {
		pr_err("[vicky] failed at [%s]: %d\n", __FUNCTION__, __LINE__);
		return -EINVAL;
	}
	
	smp_rmb();
	switch (hdr[3] & DW_EH_PE_FORM) {
	case DW_EH_PE_native:
		tableSize = sizeof(unsigned long);
		break;
	case DW_EH_PE_data2:
		tableSize = 2;
		break;
	case DW_EH_PE_data4:
		tableSize = 4;
		break;
	case DW_EH_PE_data8:
		tableSize = 8;
		break;
	default:
		tableSize = 0;
		break;
	}

	ptr = hdr + 4;
	end = hdr + table->hdrsz;

	if (tableSize == 0 ||
	    read_pointer(&ptr, end, hdr[1], kern_base, user_base) !=
		    (unsigned long)table->address ||
	    (fde_count = read_pointer(&ptr, end, hdr[2], kern_base,
				      user_base)) <= 0 ||
	    fde_count != (end - ptr) / (2 * tableSize) ||
	    ((end - ptr) % (2 * tableSize))) {
		pr_err("[vicky] failed at [%s]: %d\n", __FUNCTION__, __LINE__);
		return -EINVAL;
	}
	pr_debug("[hsuck] table name=%s, nFDE=%u\n", table->info->name,
		 fde_count);

	temp_ptr = (struct eh_frame_hdr_table_entry *)ptr;
	bs_l = 0, bs_r = fde_count - 1;
	while (bs_l <= bs_r) {
		bs_mid = (bs_l + bs_r) / 2;
		if (temp_ptr[bs_mid].start < pc_kern) {
			bs_l = bs_mid + 1;
		} else if (temp_ptr[bs_mid].start > pc_kern) {
			bs_r = bs_mid - 1;
		} else {
			bs_r = bs_mid;
			break;
		}
	}
	if (bs_r < 0) {
		pr_err("[vicky] binary search failed.\n");
		return -EINVAL;
	}
	/* Get the start address of BL target and corresponding FDE */
	startLoc = temp_ptr[bs_r].start;
	fde = (const u32 *)temp_ptr[bs_r].fde;
	pr_debug("[vicky] binSearch found startLoc = %lx, fde = %lx\n",
		 translate_kern_to_user(kern_base, user_base, startLoc),
		 translate_kern_to_user(kern_base, user_base,
					(const unsigned long)fde));

	//startLoc = FDE pc begin
	//fde = fde addr
	if (fde != NULL) {
		cie = cie_for_fde(fde);
		ptr = (const u8 *)(fde + 2);
		if (cie == NULL || cie == &bad_cie || cie == &not_fde) {
			pr_err("[vicky] failed at [%s]: %d, cie is %px\n",
			       __FUNCTION__, __LINE__, cie);
			return -EINVAL;
		} else if ((ptrType = fde_pointer_type(cie, kern_base,
						       user_base)) < 0) {
			pr_err("[vicky] failed at [%s]: %d, ptrType = %d\n",
			       __FUNCTION__, __LINE__, ptrType);
			return -EINVAL;
		} else if ((temp = read_pointer(
				    &ptr, (const u8 *)(fde + 1) + *fde, ptrType,
				    kern_base, user_base)) != startLoc) {
			pr_err("[vicky] failed at [%s]: %d, "
			       "error startLoc = %lx, correct startLoc = %lx\n",
			       __FUNCTION__, __LINE__, temp, startLoc);
			return -EINVAL;
		} else {
			if (!(ptrType & DW_EH_PE_indirect))
				ptrType &= DW_EH_PE_FORM | DW_EH_PE_signed;
			/* Get the end address of BL target */
			endLoc = startLoc +
				 read_pointer(&ptr,
					      (const u8 *)(fde + 1) + *fde,
					      ptrType, kern_base, user_base);
			if (pc_kern >= endLoc || pc_kern < startLoc) {
				pr_err("[vicky] failed at [%s]: %d, "
				       "startLoc = %lx, pc = %lx, endLoc = %lx\n",
				       __FUNCTION__, __LINE__,
				       translate_kern_to_user(
					       kern_base, user_base, startLoc),
				       pc,
				       translate_kern_to_user(
					       kern_base, user_base, endLoc));
				return -EINVAL;
			}
		}
	}

	startLoc = translate_kern_to_user(kern_base, user_base, startLoc);
	endLoc = translate_kern_to_user(kern_base, user_base, endLoc);
	temp = UNW_PC(frame);
	pr_debug("[hsuck] start=%#0lx, end=%#0lx, pc=%#0lx\n", startLoc, endLoc,
		 temp);
	for (addr = startLoc; addr < endLoc; addr += 4) {
		insn = extract_insn(addr);
		if (insn == (unsigned long)-EFAULT)
			return -EFAULT;

		insn_type = extract32(insn, 25, 4);
		pr_debug("[hsuck] %#0lx: insn=%#0x, type=%#0x\n", addr, insn,
			 insn_type);
		/* Branch insns */
		if (insn_type == 0xa || insn_type == 0xb) {
			switch (extract32(insn, 25, 7)) {
			case 0x0a: case 0x0b:
			case 0x4a: case 0x4b:
				/* BL Branch with link */
				if (insn & (1U << 31)) {
					pr_debug("[hsuck] bl insn\n");
					goto loop_end;
				}
				/* B Branch */
				pr_debug("[hsuck] b insn\n");
				break;
			case 0x6b:
				switch (extract32(insn, 21, 4)) {
				case 0:
					pr_debug("[hsuck] br insn\n");
					break;
				case 1:
					pr_debug("[hsuck] blr insn\n");
					goto loop_end;
				default:
					pr_debug("[hsuck] other type\n");
					goto loop_end;
				}
				break;
			default:
				goto loop_end;
			}

			b_target = disas_b_insns(frame, addr, insn);
			pr_debug("[hsuck] branch target=%#0lx\n", b_target);
			/* In same function */
			if (b_target >= startLoc && b_target < endLoc)
				goto loop_end;

			if (b_target == entry_point) {
				pr_debug("[hsuck] found correct branch: "
					 "bl target=%#0lx, b target=%#0lx, "
					 "entry=%#0lx\n",
					 UNW_PC(frame), b_target, entry_point);
				retval = 0;
				break;
			}

			UNW_PC(frame) = b_target;
			retval = find_all_branches(phtable, frame, entry_point,
						   depth - 1);
			UNW_PC(frame) = temp;
			if (retval == 0)
				break;
		}
loop_end:
	}

	return retval;
}

static int callsite_checking(struct hash_table *phtable,
			     struct unwind_frame_info *frame)
{
	int retval;
	unsigned long addr, bl_target, start, end,
		entry_point = frame->entry_point;
	unsigned long temp = 0;
	unsigned int insn, insn_type;
	const table_t *table;

	/* Read the insn above the ra */
	addr = UNW_PC(frame) - 4;
	insn = extract_insn(addr);
	if (insn == (unsigned long)-EFAULT) {
		retval = -1;
		goto out;
	}

	insn_type = extract32(insn, 25, 4);
	pr_debug("[hsuck] %#0lx: insn=%#0x, type=%#0x\n", addr, insn,
		 insn_type);

	/* Whether it is really a branch instruction */
	if (insn_type == 0xa || insn_type == 0xb)
		bl_target = disas_b_insns(frame, addr, insn);

	if (!bl_target) {
		retval = -1;
		goto out;
	} else if (bl_target == -1) { /* Branch by register */
		retval = 0;
		goto out;
	}

	/* b insn workaround */
	if (entry_point == frame->base_addr + IO_FGETS_ENTRY)
		entry_point = frame->base_addr + IO_FOPEN_ENTRY;

	if (entry_point == frame->base_addr + PTHREAD_ONCE_ENTRY)
		entry_point = frame->base_addr + PTHREAD_ONCE_ENTRY;

	pr_debug("[hsuck] call target: %#0lx, entry point: %#0lx\n", bl_target,
		 entry_point);

	/* Compare call target with function entry point */
	if (bl_target == entry_point) {
		if (!is_stp(bl_target))
			pr_debug("[ztex] %d: %#0lx is a function allocating no space\n",
				 __LINE__, bl_target);
		goto out_print_suc;
	} else {
		table = find_table(phtable, frame);
		if (!table) {
			pr_err("[ztex] %s:%d fail to find the corresponding table, pc: %lx\n",
			       __FUNCTION__, __LINE__, UNW_PC(frame));
			retval = -1;
			goto out_print_err;
		}

		if (!table->info->plt_found) {
			pr_debug("[ztex] %s: we did not find .plt section previously\n", 
				 table->info->name);
			retval = -1;
			addr = bl_target;
			goto find_b;
		}

		addr = bl_target;
		start = table->info->base_address + table->info->plt_start;
		end = start + table->info->plt_size;
		if (addr < start || addr >= end) {
			pr_debug("[hsuck] call target %#0lx is not a plt entry\n",
				 addr);
			retval = -1;
			goto find_b;
		}

		bl_target = extract_target_from_plt(addr);
		if (bl_target == entry_point)
			goto out_print_suc;
		else
			addr = bl_target;
find_b:
		temp = UNW_PC(frame);
		UNW_PC(frame) = addr;
		retval = find_all_branches(phtable, frame, entry_point, 3);
		UNW_PC(frame) = temp;
		if (!retval)
			goto out_print_suc;
		else
			goto out_print_err;
	}
out:
	return retval;
out_print_err:
	pr_err("[hsuck] callsite checking failed, "
	       "addr=%#0lx, target=%#0lx, entry=%#0lx, insn type=%#0x\n",
	       UNW_PC(frame) - 4, bl_target, frame->entry_point,
	       extract32(insn, 25, 7));
	goto out;
out_print_suc:
	pr_debug("[hsuck] %d: callsite checking successed, "
		 "addr=%#0lx, target=%#0lx, entry=%#0lx\n",
		 __LINE__, UNW_PC(frame) - 4, bl_target, entry_point);
	retval = 0;
	goto out;
}

int delta_enforce_verification(struct hash_table *phtable,
			       struct unwind_frame_info *frame)
{
	int retval;

	if (!delta_app_inlist)
		delta_app_inlist = (void *)__kallsyms_lookup_name("delta_app_inlist");	

	/* Unwinding until reach main() */
	while (1) {
		retval = delta_unwind(phtable, frame);
		if (retval == -EINVAL || retval == -EIO || retval == -EFAULT) {
			/* Abort the process */
			pr_err("[hsuck] unwinding failed at pc: %#0lx\n",
			       UNW_PC(frame));
			break;
		}

		/* Reached the entry point of the program */
		if (retval == 1) {
			pr_debug("[hsuck] unwinding sucessfully reached main: %#0lx\n",
				 frame->entry_point);
			break;
		} else if (retval == 2 && delta_app_inlist(current->parent)) {
			pr_debug("[hsuck] unwinding sucessfully reached __clone: %#0lx\n",
				 frame->entry_point);
			break;
		}

		retval = callsite_checking(phtable, frame);
		/* if (retval == -1) */
		/* 	break; */
	}
	return retval;
}
EXPORT_SYMBOL(delta_enforce_verification);

static int rootkit_open(struct inode *inode, struct file *filp)
{
	pr_info("[hsuck] %s\n", __FUNCTION__);
	return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp)
{
	pr_info("[hsuck] %s\n", __FUNCTION__);
	return 0;
}

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
			  unsigned long arg)
{
	pr_info("[hsuck] %s\n", __FUNCTION__);
	return 0;
}
struct file_operations fops = {
	open: rootkit_open,
	unlocked_ioctl: rootkit_ioctl,
	release: rootkit_release,
	owner: THIS_MODULE
};

static struct miscdevice sandbox_unwind = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sandbox_unwind",
	.fops = &fops,
	.mode = 0664,
};

static int __init sandbox_unwind_init(void) { 
	int ret;

	if ((ret = misc_register(&sandbox_unwind)) < 0)
		pr_err("[hsuck] misc_register failed, ret = %d\n", ret);

	pr_info("[vicky] successfully init %s\n", OURMODNAME);

	register_kprobe(&kp);
	__kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	traverse_vma = NULL;
	delta_app_inlist = NULL;

	return 0; 
}
static void __exit sandbox_unwind_exit(void) { 
	pr_info("[vicky] %s: removed\n", OURMODNAME);
	misc_deregister(&sandbox_unwind);
	return;
}

module_init(sandbox_unwind_init);
module_exit(sandbox_unwind_exit);

MODULE_AUTHOR("hsuck <r11944008@csie.ntu.edu.tw>");
MODULE_DESCRIPTION("Delta sandbox system call protection");
MODULE_LICENSE("GPL");
MODULE_VERSION(SANDBOX_VERSION);
