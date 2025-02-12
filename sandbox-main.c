#include <linux/sched.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/timekeeping.h>
#include <linux/elf.h>
#include <linux/kprobes.h>
#include <asm/syscall.h>
#include "sandbox.h"
#include "sandbox-unwind.h"

#define SANDBOX_VERSION "0.1"
#define OURMODNAME "sandbox"

#define MAGIC 'k'
#define IOCTL_MOD_PASS _IO(MAGIC, 0)
#define IOCTL_ENABLE_UNWIND _IO(MAGIC, 1)
#define IOCTL_DISABLE_UNWIND _IO(MAGIC, 2)

#define MAX_NAME 50

#define ELFOSABI_ARM_FDPIC 65 /* ARM FDPIC platform */
#define elf_check_fdpic(x) ((x)->e_ident[EI_OSABI] == ELFOSABI_ARM_FDPIC)

#define CLONE_ENTRY 0xea5d0

unsigned int num_apps = 10;
char *hook_apps[] = { "httpd",	  "nginx",     "sqlite-bench", "omnetpp",
		      "cpuxalan", "deepsjeng", "leela",	       "namd",
		      "povray",	  "test2" };

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t __kallsyms_lookup_name;

static int syscall_hooked = 0;
static unsigned long *__sys_call_table;
spinlock_t sandbox_spinlock;
struct mutex sandbox_mutex;

void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt,
			    phys_addr_t size, pgprot_t prot);
struct vm_area_struct *(*__find_vma_prev)(struct mm_struct *mm,
					  unsigned long addr,
					  struct vm_area_struct **pprev);
struct task_struct *(*__find_get_task_by_vpid)(pid_t nr);

typedef asmlinkage long (*sys_call_t)(const struct pt_regs *);
static sys_call_t orig_openat, orig_read, orig_write, orig_recvfrom,
	orig_sendfile, orig_readv, orig_writev;
static sys_call_t orig_execve, orig_execveat, orig_clone;
static sys_call_t orig_mprotect, orig_mmap, orig_mremap;
static sys_call_t orig_socket, orig_bind, orig_connect, orig_listen,
	orig_accept, orig_accept4;
static sys_call_t orig_exit, orig_exit_group;

static struct hash_table *search_htable(const char *, const pid_t);
static int create_htable(const char *, const pid_t, bool);

static struct so_info *search_item(struct hash_table *, const char *);
static int insert_item(struct hash_table *, const char *);

static int elf_read(struct file *file, void *buf, size_t len, loff_t pos);
static struct elf_shdr *load_elf_shdrs(const struct elfhdr *elf_ex,
				       struct file *elf_file);
static struct elf_shdr *elf_find_strtab(const struct elfhdr *elf_ex,
					struct elf_shdr *elf_shdata);
static char *elf_fetch_tab(struct file *elf_file, struct elf_shdr *elf_shtab);
static void elf_get_so(struct elf_shdr *elf_shdynamic, char *dynamic,
		       char *strtab, struct hash_table *phtable);
static char *_lib_fetch_ehframe(struct file *file, struct so_info *cur,
				struct hash_table *phtable);
static void lib_fetch_ehframe(const char *libname, struct file *libfile,
			      struct hash_table *phtable);

DECLARE_HASHTABLE(proc_htable, 16);

static struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

// TODO: ztex, we should make the app list an array
inline int delta_app_inlist(const char *task_comm)
{
	int i;
	for (i = 0; i < num_apps; ++i) {
		if (strstr(task_comm, hook_apps[i]))
			return 1;
	}
	return 0;
}

char *get_task_full_comm(const struct task_struct *t)
{
	char *temp = NULL, *filepath = NULL, *p;
	struct mm_struct *mm;

	mm = get_task_mm(current);
	if (mm) {
		down_read(&mm->mmap_lock);
		if (mm->exe_file) {
			temp = kzalloc(PATH_MAX, GFP_KERNEL);
			if (!temp) {
				pr_err("[hsuck] %s, L%d buffer allocation failed\n",
				       __FUNCTION__, __LINE__);

				goto out;
			}

			p = file_path(mm->exe_file, temp, PATH_MAX);

			filepath = kzalloc(strlen(p) + 1, GFP_KERNEL);
			if (!filepath) {
				pr_err("[hsuck] %s, L%d buffer allocation failed\n",
				       __FUNCTION__, __LINE__);
				goto out;
			}
			strncpy(filepath, p, strlen(p));
		}
		up_read(&mm->mmap_lock);
	}

	kfree(temp);
	return filepath;
out:
	up_read(&mm->mmap_lock);
	RELEASE_MEMORY(temp);
	return NULL;
}

#if DEBUG_SANDBOX > 0
static void hexdump(char *buffer, unsigned long size)
{
	while (size >= 8) {
		pr_debug(
			"[ztex] %px: %02x %02x %02x %02x %02x %02x %02x %02x\n",
			buffer, buffer[0], buffer[1], buffer[2], buffer[3],
			buffer[4], buffer[5], buffer[6], buffer[7]);
		buffer += 8;
		size -= 8;
	}
}
#endif // DEBUG_SANDBOX

static int open_by_self(struct hash_table *phtable, unsigned long pc)
{
	/* FIXME hsuck: may need more aliases*/
	char *ldname = "ld-linux-aarch64.so.1";
	char *rtlib = "librtlib.so";
	struct so_info *cur;

	cur = search_item(phtable, ldname);
	/* FIXME hsuck: may static link or not found */
	if (!cur)
		return 1;

	pr_debug("[hsuck] %s, L%d: pc=%#0lx, range=[%#0lx-%#0lx]\n",
		 __FUNCTION__, __LINE__, pc, cur->base_address,
		 cur->base_address + cur->pc_range);
	if (pc >= cur->base_address && pc < cur->base_address + cur->pc_range)
		return 0;

	cur = search_item(phtable, rtlib);
	if (!cur)
		return 1;

	if (pc >= cur->base_address && pc < cur->base_address + cur->pc_range)
		return 0;

	return 1;
}

static void unwind_stack(struct hash_table *phtable)
{
	struct pt_regs *regs;
	struct unwind_frame_info *frame;
	struct so_info *proc_info;
	unsigned long addr, size;
	int retval;
	char *ehframe;

	proc_info = search_item(phtable, phtable->name);
	if (!proc_info) {
		pr_err("[hsuck] %s, L%d: %s, item not found\n", __FUNCTION__,
		       __LINE__, phtable->name);
		goto out;
	}

	if (proc_info->ehframe)
		goto unwind_table;

	pr_debug("[hsuck] fetching .eh_frame of %s\n", phtable->name);
	if (proc_info->eh_frame_found != 1) {
		pr_err("[ztex] we did not find .eh_frame section previously\n");
		goto out;
	}

	addr = proc_info->base_address + proc_info->eh_frame_start;
	size = proc_info->eh_frame_size;
	pr_debug("[hsuck] .eh_frame: size=%lu, addr=%#0lx\n", size, addr);

	ehframe = kzalloc(size, GFP_KERNEL);
	if (!ehframe) {
		pr_err("[hsuck] %s, L%d: buffer allocation failed\n",
		       __FUNCTION__, __LINE__);
		goto out;
	}

	if (copy_from_user(ehframe, (void __user *)addr, size)) {
		pr_err("[hsuck] %s, L%d: failed to read from user space, "
		       "addr: %lx, size: %lx\n",
		       __FUNCTION__, __LINE__, addr, size);
		goto out_free_ehf;
	}
	proc_info->ehframe = ehframe;

unwind_table:
	if (phtable->root_table)
		goto unwinding;

	phtable->root_table = kmalloc(sizeof(table_t), GFP_KERNEL);
	if (!phtable->root_table) {
		pr_err("[hsuck] %s, L%d buffer allocation failed\n",
		       __FUNCTION__, __LINE__);
		goto out;
	}
	phtable->root_table->address = 0x0;
	phtable->root_table->size    = 0x0;
	phtable->root_table->header  = NULL;
	phtable->root_table->hdrsz   = 0x0;
	phtable->root_table->info    = 0x0;
	phtable->root_table->next    = phtable->root_table;
	phtable->root_table->prev    = phtable->root_table;

unwinding:
	regs = task_pt_regs(current);
	frame = kmalloc(sizeof(struct unwind_frame_info), GFP_KERNEL);
	if (!frame) {
		pr_err("[hsuck] %s, L%d: buffer allocation failed\n",
		       __FUNCTION__, __LINE__);
		return;
	}
	memcpy(&frame->regs, regs->regs, sizeof(unsigned long) * 31);
	frame->regs.sp     = regs->sp;
	frame->regs.pc     = regs->pc;
	frame->regs.pstate = regs->pstate;
	frame->task        = current;

#if MEASURE_TIME == 1
	ktime_get_ts64(&begin);
#endif
	if (!phtable->is_inited)
		init_unwind_table(phtable, frame);
#if MEASURE_TIME == 1
	ktime_get_ts64(&end);
	ts = timespec64_sub(end, begin);
	pr_info("[hsuck] time spent for init_unwind_table, %lld (ns) elapsed\n",
		timespec64_to_ns(&ts));
#endif

#if MEASURE_TIME == 1
	ktime_get_ts64(&begin);
#endif
	retval = delta_enforce_verification(phtable, frame);
#if MEASURE_TIME == 1
	ktime_get_ts64(&end);
	ts = timespec64_sub(end, begin);
	pr_info("[hsuck] time spent for delta_enforce_verification, %lld (ns) elapsed\n",
		timespec64_to_ns(&ts));
#endif

	/* if (retval == -1) { */
	/*	pr_debug("[hsuck] kill the process %d\n", task_pid_nr(current)); */
	/*	do_exit(-1); */
	/* } */

	kfree(frame);
out:
	
	return;
out_free_ehf:
	kfree(ehframe);
	proc_info->ehframe = NULL;
}

static void fill_base(struct hash_table *phtable, const char *libname,
		      unsigned long base_address, unsigned long size)
{
	struct so_info *cur;

	if (!libname || !base_address || !size) {
		pr_debug("[hsuck] %s, L%d: %s(%d) %s %ld %ld\n", __FUNCTION__,
			 __LINE__, phtable->name, task_pid_nr(current),
			 libname, base_address, size);
		return;
	}

	cur = search_item(phtable, libname);
	if (!cur) {
		pr_debug("[hsuck] %s, L%d: %s is not found\n", __FUNCTION__,
			 __LINE__, libname);
		return;
	}

	if (cur->base_address && cur->pc_range) {
		pr_debug("[hsuck] %s, L%d: %s, already filled\n", __FUNCTION__,
			 __LINE__, cur->name);
		goto out;
	}

	cur->base_address = base_address;
	cur->pc_range = size;

out:
	if (cur->base_address < cur->eh_frame_start)
		cur->eh_frame_start -= cur->base_address;

	if (strcmp(phtable->name, cur->name) == 0 && phtable->elf_entry_found &&
	    cur->base_address > phtable->elf_entry)
		phtable->elf_entry += cur->base_address;

	if (strcmp(phtable->name, cur->name) == 0 && phtable->start &&
	    cur->base_address > phtable->start)
		phtable->start += cur->base_address;

	pr_debug("[hsuck] %s, elf entry: %#0lx, _start: %#0lx\n", phtable->name,
		 phtable->elf_entry, phtable->start);

	pr_debug("[hsuck] %s: dump info of %s\n", __FUNCTION__, cur->name);
	pr_debug("[hsuck] base addr: %#0lx, size: %#0lx, "
		 "offset: %#0lx, pc range: %#0lx\n",
		 cur->base_address, cur->eh_frame_size, cur->eh_frame_start,
		 cur->pc_range);

	return;
}

int traverse_vma(struct hash_table *phtable, unsigned long pc)
{
	char *p, prev_p[256];
	unsigned long addr = 0, size = 0;
	short first = 1;
	struct mm_struct *mm;
	struct vm_area_struct *vma, *prev;

	mm = get_task_mm(current);
	if (!mm) {
		pr_err("[hsuck] mm not found\n");
		return -EINVAL;
	}

	if (!mmap_read_trylock(mm))
		return -EAGAIN;

redo:
	/* ref: https://lore.kernel.org/all/20220426150616.3937571-69-Liam.Howlett@oracle.com/ */
	for (vma = __find_vma_prev(mm, mm->start_code, &prev); vma;
	     vma = __find_vma_prev(mm, vma->vm_end, &prev)) {
		
		if (vma->vm_file) {
			char *buf = kmalloc(PATH_MAX + 11, GFP_KERNEL);
			if (buf) {
				p = file_path(vma->vm_file, buf, PATH_MAX + 11);
				if (IS_ERR(p))
					p = "?";
				pr_debug("[hsuck] %s[%lx+%lx] %c%c%c%c\n", p,
					 vma->vm_start,
					 vma->vm_end - vma->vm_start,
					 vma->vm_flags & VM_READ ? 'r' : '-',
					 vma->vm_flags & VM_WRITE ? 'w' : '-',
					 vma->vm_flags & VM_EXEC ? 'x' : '-',
					 vma->vm_flags & VM_MAYSHARE ? 's' :
								       'p');
			}

			if (!pc)
				goto fill;
			/* new shared object */
			if ((vma->vm_flags & VM_EXEC) && pc >= vma->vm_start &&
			    pc < vma->vm_end) {
				pr_debug(
					"[hsuck] find corresponding pc=%#0lx\n",
					pc);
				lib_fetch_ehframe(NULL, vma->vm_file, phtable);
				pc = 0;
				phtable->is_filled = 0;
				goto redo;
			}
fill:
			if (first)
				goto loop_out;

			if (strcmp(p, prev_p) != 0) {
				pr_debug("[hsuck] %s: %s, addr=%#0lx, "
					 "size=%#0lx\n",
					 __FUNCTION__, kbasename(prev_p), addr,
					 size);
				fill_base(phtable, kbasename(prev_p), addr,
					  size);
				addr = 0, size = 0;
			}
loop_out:
			if (vma->vm_flags & VM_EXEC) {
				if (addr == 0)
					addr = vma->vm_start;
				size += (vma->vm_end - vma->vm_start);
			}

			first = 0;
			memset(prev_p, '\0', 256);
			strncpy(prev_p, p, strlen(p));

			kfree(buf);
		}
	}

	if (addr && size)
		fill_base(phtable, kbasename(prev_p), addr, size);

	mmap_read_unlock(mm);

	return 0;
}

static int is_all_filled(struct hash_table *phtable)
{
	int bkt;
	struct so_info *cur;

	if (phtable->is_filled == 1)
		return 1;

	/* linear search */
	hash_for_each (phtable->htable, bkt, cur, node) {
		pr_debug("[hsuck] %s[%#0lx-%#0lx]\n", cur->name,
			 cur->base_address, cur->base_address + cur->pc_range);
		if (!cur->base_address || !cur->pc_range)
			return 0;
	}

	phtable->is_filled = 1;
	return 1;
}

/* FIXME hsuck: may need to replace with SHA256 or other hash function? */
inline static u32 myhash(const char *s)
{
	u32 key = 0;
	char c;

	while ((c = *s++))
		key += c;

	return key;
}

/**
 * search_htable() - find the corresponding hash table
 * @pname: the name of process
 * Return NULL upon failure.
 */
static struct hash_table *search_htable(const char *pname, const pid_t pid)
{
	struct hash_table *phtable;
	u32 key = myhash(pname);

	key += pid;
	hash_for_each_possible (proc_htable, phtable, node, key)
		if (strcmp(phtable->name, pname) == 0 && pid == phtable->pid)
			return phtable;
	return NULL;
}

/**
 * create_htable() - create the hash table for process
 * @pname   : the name of the process
 * @pid     : the pid of the process
 * @set_cntr: if true, create a counter for this process
 */
static int create_htable(const char *pname, const pid_t pid, bool set_cntr)
{
	int retval = -1;
	struct hash_table *phtable;
	u32 key = myhash(pname);

	key += pid;
	if (search_htable(pname, pid)) {
		pr_err("[hsuck] %s, L%d %s, %d htable has already existed\n",
		       __FUNCTION__, __LINE__, pname, pid);
		goto out;
	}

	phtable = kmalloc(sizeof(struct hash_table), GFP_KERNEL);
	if (!phtable) {
		pr_err("[hsuck] %s, L%d: buffer allocation failed\n",
		       __FUNCTION__, __LINE__);
		goto out;
	}
	memset(phtable, 0, sizeof(struct hash_table));
	hash_init(phtable->htable);

	phtable->name = kmalloc(strlen(pname) + 1, GFP_KERNEL);
	if (!phtable->name) {
		pr_err("[hsuck] %s, L%d: buffer allocation failed\n",
		       __FUNCTION__, __LINE__);
		goto out_free_phtable;
	}
	memset(phtable->name, 0, strlen(pname) + 1);
	strncpy(phtable->name, pname, strlen(pname));

	if (set_cntr) {
		phtable->cntr = kmalloc(sizeof(atomic_t), GFP_KERNEL);
		if (!phtable->cntr) {
			pr_err("[hsuck] %s, L%d: counter allocation failed\n",
			       __FUNCTION__, __LINE__);
			goto out_free_name_buf;
		}
		atomic_set(phtable->cntr, 1);
	}

	phtable->pid = pid;

	hash_add(proc_htable, &phtable->node, key);
	retval = 0;
out:
	return retval;

	/* error cleanup*/
out_free_name_buf:
	kfree(phtable->name);
out_free_phtable:
	kfree(phtable);
	goto out;
}

/**
 * search_item() - search certain item in the hash table
 * by the name of process
 * @htable: the hash table of process
 * @soname: the name of the shared object
 */
static struct so_info *search_item(struct hash_table *phtable,
				   const char *soname)
{
	struct so_info *item;
	u32 key = myhash(soname);
	hash_for_each_possible (phtable->htable, item, node, key)
		if (strcmp(item->name, soname) == 0)
			return item;

	return NULL;
}

/*
 * insert_item() - insert item to the hash table
 * @htable: the hash table of process
 * @soname: the name of the shared object
 * @value : the address of struct so_info
 */
static int insert_item(struct hash_table *phtable, const char *soname)
{
	int retval = -1;
	struct so_info *item;
	u32 key = myhash(soname);

	item = kmalloc(sizeof(struct so_info), GFP_KERNEL);
	if (!item) {
		pr_err("[hsuck] %s, %d: buffer allocation failed\n",
		       __FUNCTION__, __LINE__);
		goto out;
	}
	memset(item, 0, sizeof(struct so_info));

	item->name = kmalloc(strlen(soname) + 1, GFP_KERNEL);
	if (!item->name) {
		pr_err("[hsuck] %s, %d: buffer allocation failed\n",
		       __FUNCTION__, __LINE__);
		goto out_free_item;
	}
	memset(item->name, 0, strlen(soname) + 1);
	strncpy(item->name, soname, strlen(soname));

	hash_add(phtable->htable, &item->node, key);
	retval = 0;
out:
	return retval;
out_free_item:
	kfree(item);
	goto out;
}

static void fill_child_entry(struct hash_table *phtable)
{
	struct so_info *item;
	char libname[128] = "libc.so.6";

	item = search_item(phtable, libname);
	if (!item) {
		pr_debug("[hsuck] %s: %s is not found\n", __FUNCTION__,
			 libname);
		return;
	}

	phtable->clone_entry = item->base_address + CLONE_ENTRY;
	pr_debug("[hsuck] clone entry: %#0lx\n", phtable->clone_entry);

	item = search_item(phtable, phtable->name);
	if (!item) {
		pr_debug("[hsuck] %s: %s is not found\n", __FUNCTION__,
			 phtable->name);
		return;
	}

	if (!strcmp("httpd", phtable->name) && phtable->child_main &&
	    item->base_address > phtable->child_main) {
		phtable->child_main += item->base_address;
		pr_debug("[hsuck] child_main: %#0lx\n", phtable->child_main);
	}

	return;
}

static void syscall_protection(void)
{
	char *filepath = get_task_full_comm(current);
	int retval, bkt;
	struct hash_table *phtable;
	struct pt_regs *regs;
	struct so_info *cur;

	pr_debug("[hsuck] task is %s, pid=%d, ppname=%s, ppid=%d\n",
		 kbasename(filepath), task_pid_nr(current),
		 current->real_parent->comm, task_pid_nr(current->real_parent));

	mutex_lock(&sandbox_mutex);
	mutex_unlock(&sandbox_mutex);
	phtable = search_htable(kbasename(filepath), task_pid_nr(current));
	if (!phtable || hash_empty(phtable->htable)) {
		pr_err("[hsuck] %s, %d: %s(%d), hash table is NULL or no entries\n",
		       __FUNCTION__, __LINE__, kbasename(filepath),
		       task_pid_nr(current));
		goto out;
	}

	/* if (phtable->is_static) { */
	/* 	pr_debug("[hsuck] static linked\n"); */
	/* 	goto unwind; */
	/* } */

	/* if (!phtable->is_filled) { */
	/* 	do { */
	/* 		retval = traverse_vma(phtable, 0); */
	/* 	} while (retval == -EAGAIN); */

	/* 	phtable->is_filled = 1; */
	/* } */

	/* if (phtable->is_filled && */
	/*     (!phtable->clone_entry || !phtable->child_main)) { */
	/* 	cur = search_item(phtable, "libc.so.6"); */
	/* 	if (cur) { */
	/* 		phtable->clone_entry = cur->base_address + CLONE_ENTRY; */
	/* 		pr_debug("[hsuck] clone entry: %#0lx\n", */
	/* 			 phtable->clone_entry); */
	/* 	} */

	/* 	if (!strcmp("httpd", phtable->name)) { */
	/* 		cur = search_item(phtable, phtable->name); */
	/* 		if (phtable->child_main && */
	/* 		    cur->base_address > phtable->child_main) { */
	/* 			phtable->child_main += cur->base_address; */
	/* 			pr_debug("[hsuck] child_main: %#0lx\n", */
	/* 				 phtable->child_main); */
	/* 		} */
	/* 	} */
	/* } */

	switch (is_all_filled(phtable)) {
	case 0:
		pr_debug("[hsuck] have not filled\n");
		do {
			retval = traverse_vma(phtable, 0);
		} while (retval == -EAGAIN);
		break;
	case 1:
		pr_debug("[hsuck] have filled\n");
		fill_child_entry(phtable);
		break;
	default:
		break;
	}

	regs = task_pt_regs(current);
	/* cur = search_item(phtable, "ld-linux-aarch64.so.1"); */
	/* if (cur) */
	/* 	if (regs->pc < cur->base_address || */
	/* 	    regs->pc >= cur->base_address + cur->pc_range) */
	/* 		goto out; */

	/* cur = search_item(phtable, "librtlib.so"); */
	/* if (cur) */
	/* 	if (regs->pc < cur->base_address || */
	/* 	    regs->pc >= cur->base_address + cur->pc_range) */
	/* 		goto out; */

	switch (open_by_self(phtable, regs->pc)) {
	case 0:
		pr_debug("[hsuck] not open by itself\n");
		goto out;
	case 1:
		pr_debug("[hsuck] open by itself\n");
		break;
	default:
		break;
	}

unwind:
	unwind_stack(phtable);

out:
	kfree(filepath);
	return;
}

static int elf_read(struct file *file, void *buf, size_t len, loff_t pos)
{
	ssize_t rv;

	rv = kernel_read(file, buf, len, &pos);
	if (unlikely(rv != len)) {
		return (rv < 0) ? rv : -EIO;
	}
	return 0;
}

/**
 * load_elf_shdrs() - load ELF section headers
 * @elf_ex:   ELF header of the binary whose program headers should be loaded
 * @elf_file: the opened ELF binary file
 *
 * Loads ELF section headers from the binary file elf_file, which has the ELF
 * header pointed to by elf_ex, into a newly allocated array. The caller is
 * responsible for freeing the allocated data. Returns NULL upon failure.
 */
static struct elf_shdr *load_elf_shdrs(const struct elfhdr *elf_ex,
				       struct file *elf_file)
{
	struct elf_shdr *elf_shdata = NULL;
	int retval = -1;
	unsigned int size;

	if (elf_ex->e_shentsize != sizeof(struct elf_shdr))
		goto out;

	size = sizeof(struct elf_shdr) * elf_ex->e_shnum;
	pr_debug("[hsuck] %s, L%d: size: %u, offset: %llu\n", __FUNCTION__,
		 __LINE__, size, (unsigned long long)elf_ex->e_shoff);

	elf_shdata = kmalloc(size, GFP_KERNEL);
	if (!elf_shdata)
		goto out;

	/* Read in the section headers */
	retval = elf_read(elf_file, elf_shdata, size, elf_ex->e_shoff);

out:
	if (retval) {
		kfree(elf_shdata);
		elf_shdata = NULL;
	}
	return elf_shdata;
}

/**
 * elf_find_strtab() - find the elf section header for the string table
 * @elf_shdata: the start of the section header table
 *
 * Return NULL upon failure.
 */
static struct elf_shdr *elf_find_strtab(const struct elfhdr *elf_ex,
					struct elf_shdr *elf_shdata)
{
	if (!elf_ex || !elf_shdata)
		return NULL;
	return &(elf_shdata[elf_ex->e_shstrndx]);
}

/**
 * elf_fetch_tab() - find the specified table
 * @elf_shtab: the section header for table
 * @elf_file: the opened ELF binary file
 * Caller is responsible for freeing the buffer. Return NULL upon failure.
 */
static char *elf_fetch_tab(struct file *elf_file, struct elf_shdr *elf_shtab)
{
	char *tab = NULL;
	int retval = -1;
	unsigned int size;
	if (!elf_shtab || !elf_file)
		goto out;
	size = elf_shtab->sh_size;

	tab = kmalloc(size, GFP_KERNEL);
	if (!tab) {
		pr_err("[hsuck] %s, %d: fucking ass\n", __FUNCTION__, __LINE__);
		goto out;
	}
	pr_debug("[hsuck] %s: size: %u, offset: %llu\n", __FUNCTION__, size,
		 (unsigned long long)elf_shtab->sh_offset);
	retval = elf_read(elf_file, tab, size, elf_shtab->sh_offset);
out:
	if (retval) {
		pr_err("[hsuck] %s, %d: fucking ass\n", __FUNCTION__, __LINE__);
		kfree(tab);
		tab = NULL;
	}
	return tab;
}

/**
 * elf_get_funcsym - find the symbol given a function's name
 * @elf_shsymtab: the section table of the symbol table
 * @symtab: the character buffer of the symbol table
 * @strtab: the character buffer of the string table
 * @func_name: the function name which we're looking for
 */
static Elf64_Sym *elf_get_funcsym(struct elf_shdr *elf_shsymtab, char *symtab,
				  char *strtab, const char *func_name)
{
	int i;
	Elf64_Sym *sym;
	char *name;

	if (!elf_shsymtab || !symtab || !strtab)
		return NULL;

	for (i = 1; i < elf_shsymtab->sh_size / elf_shsymtab->sh_entsize; ++i) {
		sym = (Elf64_Sym *)(symtab + i * elf_shsymtab->sh_entsize);
		name = strtab + sym->st_name;

		if (!strlen(name) || ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
			goto loop_end;

		if (strcmp(func_name, name) == 0) {
			return sym;
		}
loop_end:
		sym = NULL;
	}
	return NULL;
}

static char *_lib_fetch_ehframe(struct file *file, struct so_info *cur,
				struct hash_table *phtable)
{
	struct elf_shdr *elf_shstrtab, *elf_shdata, *elf_shent;
	struct elf_shdr *elf_shdynamic = NULL;
	struct elfhdr elf_ex;
	int retval, i;
	char *shstrtab = NULL;
	char *ehframe = NULL;
	char *dynstr = NULL;
	char *dynamic = NULL;

	retval = elf_read(file, &elf_ex, sizeof(elf_ex), 0);
	if (retval < 0)
		goto out;

	if (memcmp(elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
		goto out;

	/* First of all, some simple consistency checks */
	if (elf_ex.e_type != ET_DYN)
		goto out;
	if (!elf_check_arch(&elf_ex))
		goto out;
	if (elf_check_fdpic(&elf_ex))
		goto out;
	if (!file->f_op->mmap)
		goto out;

	/* Find the section header table */
	elf_shdata = load_elf_shdrs(&elf_ex, file);
	if (!elf_shdata) {
		pr_err("[ztex] fail to load section table\n");
		goto out;
	}
	elf_shstrtab = elf_find_strtab(&elf_ex, elf_shdata);
	if (!elf_shstrtab) {
		pr_err("[ztex] fail to find the section header for string table\n");
		goto out_free_shdata;
	}
	shstrtab = elf_fetch_tab(file, elf_shstrtab);
	if (!shstrtab) {
		pr_err("[ztex] fail to find the string table\n");
		goto out_free_shdata;
	}

	elf_shent = elf_shdata;
	for (i = 0; i < elf_ex.e_shnum; i++, elf_shent++) {
		if (strcmp(".eh_frame", shstrtab + elf_shent->sh_name) == 0) {
			ehframe = elf_fetch_tab(file, elf_shent);
			if (!ehframe) {
				pr_err("[ztex] cannot found .eh_frame\n");
			}
			pr_debug("[ztex] found .eh_frame\n");
			pr_debug("[hsuck] start: %#0llx, size: %#0llx\n",
				 elf_shent->sh_addr, elf_shent->sh_size);
			cur->eh_frame_start = elf_shent->sh_addr;
			cur->eh_frame_size = elf_shent->sh_size;
			cur->eh_frame_found = 1;
			continue;
		}
		if (strcmp(".plt", shstrtab + elf_shent->sh_name) == 0) {
			pr_debug("[ztex] found .plt\n");
			cur->plt_start = elf_shent->sh_addr;
			cur->plt_size = elf_shent->sh_size;
			cur->plt_found = 1;
			continue;
		}
		if (strcmp(".dynstr", shstrtab + elf_shent->sh_name) == 0) {
			dynstr = elf_fetch_tab(file, elf_shent);
			if (!dynstr) {
				pr_err("[hsuck] cannot found dynstr\n");
			}
			pr_debug("[hsuck] found .dynstr\n");
			continue;
		}
		if (strcmp(".dynamic", shstrtab + elf_shent->sh_name) == 0) {
			dynamic = elf_fetch_tab(file, elf_shent);
			if (!dynamic) {
				pr_err("[hsuck] cannot found dynamic\n");
			}
			pr_debug("[hsuck] found .dynamic\n");
			elf_shdynamic = elf_shent;
			continue;
		}
	}
	elf_get_so(elf_shdynamic, dynamic, dynstr, phtable);

	kfree(shstrtab);
	kfree(dynstr);
	kfree(dynamic);
out_free_shdata:
	kfree(elf_shdata);
out:
	return ehframe;
}

static void lib_fetch_ehframe(const char *libname, struct file *libfile,
			      struct hash_table *phtable)
{
	struct file *file = libfile;
	struct so_info *cur;
	char *buf, *p;
	char *libpath;

	if ((!libname && !libfile) || !phtable)
		return;

	if (!libname)
		goto fetch_ehframe;

	libpath = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!libpath) {
		pr_err("[hsuck] %s:%d buffer allocation failed\n", __FUNCTION__,
		       __LINE__);
		return;
	}
	if (phtable->rpath) {
		strncpy(libpath, phtable->rpath, strlen(phtable->rpath));
		strcat(libpath, "/");
		strcat(libpath, libname);
		file = filp_open(libpath, O_RDONLY | O_LARGEFILE, 0);
		if (IS_ERR(file)) {
			pr_debug("[hsuck] open %s failed\n", libpath);
			memset(libpath, '\0', PATH_MAX);
			strcpy(libpath, "/usr/lib/");
			strcat(libpath, libname);
			file = filp_open(libpath, O_RDONLY | O_LARGEFILE, 0);
			if (IS_ERR(file)) {
				pr_err("[hsuck] open %s failed\n", libpath);
				return;
			}
		}
	} else {
		strcpy(libpath, "/usr/lib/");
		strcat(libpath, libname);
		file = filp_open(libpath, O_RDONLY | O_LARGEFILE, 0);
		if (IS_ERR(file)) {
			pr_err("[hsuck] open %s failed\n", libpath);
			return;
		}
	}

	kfree(libpath);

	/* FIXME hsuck: may need more checking? */
	if (WARN_ON_ONCE(!S_ISREG(file_inode(file)->i_mode)))
		goto out;
fetch_ehframe:
	buf = kmalloc(PATH_MAX + 11, GFP_KERNEL);
	if (buf) {
		/* get the path of SO */
		p = file_path(file, buf, PATH_MAX + 11);
		if (IS_ERR(p))
			p = "?";

		/* the SO have been processed, skip it */
		if (search_item(phtable, kbasename(p)))
			goto out;

		pr_debug("[hsuck] shared object: %s\n", kbasename(p));
		/* allocate a node for this SO */
		cur = kmalloc(sizeof(struct so_info), GFP_KERNEL);
		if (!cur) {
			pr_err("[hsuck] %s, L%d fail to allocate struct so_info\n",
			       __FUNCTION__, __LINE__);
			goto out;
		}
		memset(cur, 0, sizeof(struct so_info));

		/* insert this node into the hash table */
		insert_item(phtable, kbasename(p));
	}

	if (!(cur = search_item(phtable, kbasename(p))))
		goto out;
	cur->ehframe = _lib_fetch_ehframe(file, cur, phtable);
out:
	kfree(buf);
	if (libname && file)
		filp_close(file, NULL);
	return;
}

/**
 * elf_get_so - find the list of required shared objects
 * @elf_shdynamic: the section table of the dynamic
 * @symtab: the character buffer of the dynamic
 * @strtab: the character buffer of the string table
 * @htable: the hash table of the process
 */
static void elf_get_so(struct elf_shdr *elf_shdynamic, char *dynamic,
		       char *strtab, struct hash_table *phtable)
{
	int i;
	Elf64_Dyn *dyn;
	char *name;

	if (!elf_shdynamic || !dynamic || !strtab || !phtable)
		return;

	// We need to get rpath before fetching SOs
	for (i = 0; i < elf_shdynamic->sh_size / elf_shdynamic->sh_entsize;
	     ++i) {
		dyn = (Elf64_Dyn *)(dynamic + i * elf_shdynamic->sh_entsize);
		name = strtab + dyn->d_un.d_val;
		if (strlen(name) && dyn->d_tag == DT_RPATH && !phtable->rpath) {
			phtable->rpath = kzalloc(strlen(name) + 1, GFP_KERNEL);
			if (!phtable->rpath) {
				pr_err("[hsuck] %s:%d buffer allocation failed\n",
				       __FUNCTION__, __LINE__);
				goto out;
			}
			strncpy(phtable->rpath, name, strlen(name));
			pr_info("[hsuck] %s: rpath=%s\n", __FUNCTION__,
				phtable->rpath);
		}
	}

	for (i = 0; i < elf_shdynamic->sh_size / elf_shdynamic->sh_entsize;
	     ++i) {
		dyn = (Elf64_Dyn *)(dynamic + i * elf_shdynamic->sh_entsize);
		name = strtab + dyn->d_un.d_val;
		if (strlen(name) && dyn->d_tag == DT_NEEDED) {
			pr_debug("[hsuck] %s: %s\n", __FUNCTION__, name);
			lib_fetch_ehframe(name, NULL, phtable);
		}
	}
out:
	return;
}

asmlinkage long hacked_syscall(const struct pt_regs *pt_regs)
{
	unsigned int syscall_NR = pt_regs->user_regs.regs[8];

	if (delta_app_inlist(current->comm)) {
		pr_debug("[vicky] syscall %#0x is hooked, %s(%d)\n", syscall_NR,
			 current->comm, task_pid_nr(current));
		syscall_protection();
	}

	switch (syscall_NR) {
	case __NR_openat:
		return orig_openat(pt_regs);
	case __NR_read:
		return orig_read(pt_regs);
	case __NR_write:
		return orig_write(pt_regs);
	case __NR_readv:
		return orig_readv(pt_regs);
	case __NR_writev:
		return orig_writev(pt_regs);
	case __NR_sendfile:
		return orig_sendfile(pt_regs);
	case __NR_recvfrom:
		return orig_recvfrom(pt_regs);
	case __NR_mprotect:
		return orig_mprotect(pt_regs);
	case __NR_mmap:
		return orig_mmap(pt_regs);
	case __NR_mremap:
		return orig_mremap(pt_regs);
	case __NR_socket:
		return orig_socket(pt_regs);
	case __NR_bind:
		return orig_bind(pt_regs);
	case __NR_connect:
		return orig_connect(pt_regs);
	case __NR_listen:
		return orig_listen(pt_regs);
	case __NR_accept:
		return orig_accept(pt_regs);
	case __NR_accept4:
		return orig_accept4(pt_regs);
	default:
		pr_err("[hsuck] WTF?\n");
		break;
	}

	return -1;
}

asmlinkage long hacked_execve_family(const struct pt_regs *pt_regs)
{
	char filepath[0x100];
	char *dynamic = NULL, *dynstr = NULL, *shstrtab = NULL, *strtab = NULL,
	     *symtab = NULL;
	Elf64_Sym *sym = NULL;
	struct elf_shdr *elf_shdynamic = NULL, *elf_shsymtab = NULL,
			*elf_shdata, *elf_shent, *elf_shstrtab;
	struct elfhdr elf_ex;
	struct file *file = NULL;
	struct hash_table *htable = NULL;
	struct so_info *proc_info;
	unsigned int i, syscall_NR = pt_regs->user_regs.regs[8];
	unsigned long long filepath_addr = pt_regs->user_regs.regs[0];

	if (delta_app_inlist(current->comm)) {
		syscall_protection();
		pr_debug("[vicky] syscall `execve(at)` is hooked, %s(%d)\n",
			 current->comm, task_pid_nr(current));
	}

	/* Get file path from x0 register */
	if (copy_from_user(filepath, (void __user *)filepath_addr, 0x100)) {
		pr_err("[hsuck] %s, L%d: failed to read from user space, "
		       "addr: %llx\n",
		       __FUNCTION__, __LINE__, filepath_addr);
		goto out;
	}

	if (!delta_app_inlist(kbasename(filepath)))
		goto out;

	pr_info("[hsuck] monitoring %s(%d)\n", kbasename(filepath),
		task_pid_nr(current));

	/* Open file */
	file = filp_open(filepath, O_RDONLY | O_LARGEFILE, 0);
	if (IS_ERR(file)) {
		pr_err("[hsuck] %s, L%d: open %s failed\n", __FUNCTION__,
		       __LINE__, filepath);
		goto out;
	}
	if (WARN_ON_ONCE(!S_ISREG(file_inode(file)->i_mode)))
		goto out;

	/* Read elf header */
	if (elf_read(file, &elf_ex, sizeof(elf_ex), 0) < 0)
		goto out;

	if (memcmp(elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
		goto out;

	/* First of all, some simple consistency checks */
	if (!elf_check_arch(&elf_ex))
		goto out;
	if (elf_check_fdpic(&elf_ex))
		goto out;
	if (!file->f_op->mmap)
		goto out;

	/* Find the section header table */
	elf_shdata = load_elf_shdrs(&elf_ex, file);
	if (!elf_shdata) {
		pr_err("[ztex] fail to load section table\n");
		goto out;
	}
	elf_shstrtab = elf_find_strtab(&elf_ex, elf_shdata);
	if (!elf_shstrtab) {
		pr_err("[ztex] fail to find the section header for string table\n");
		goto out_free_shdata;
	}
	shstrtab = elf_fetch_tab(file, elf_shstrtab);
	if (!shstrtab) {
		pr_err("[ztex] fail to find the string table\n");
		goto out_free_shdata;
	}

	/* Create a hash table for the elf binary */
	pr_debug("[hsuck] create hash table for %s(%d)\n", kbasename(filepath),
		task_pid_nr(current));
	if (create_htable(kbasename(filepath), task_pid_nr(current), true) ==
	    -1) {
		pr_err("[hsuck] %s, L%d: fuck\n", __FUNCTION__, __LINE__);
		goto out_free_strtab;
	}
	if (!(htable = search_htable(kbasename(filepath),
				     task_pid_nr(current)))) {
		pr_err("[hsuck] %s, L%d: %s(%d), htable not found\n",
		       __FUNCTION__, __LINE__, kbasename(filepath),
		       task_pid_nr(current));
		goto out_free_strtab;
	}

	/* Create a hash table entry for the elf binary */
	insert_item(htable, kbasename(filepath));
	proc_info = search_item(htable, kbasename(filepath));

	elf_shent = elf_shdata;
	for (i = 0; i < elf_ex.e_shnum; i++, elf_shent++) {
		if (strcmp(".eh_frame", shstrtab + elf_shent->sh_name) == 0) {
			pr_debug("[ztex] found .eh_frame in %s\n",
				 kbasename(filepath));
			pr_debug("[hsuck] start: %#0llx, size: %#0llx\n",
				 elf_shent->sh_addr, elf_shent->sh_size);
			proc_info->eh_frame_start = elf_shent->sh_addr;
			proc_info->eh_frame_size = elf_shent->sh_size;
			proc_info->eh_frame_found = 1;
			continue;
		}
		if (strcmp(".plt", shstrtab + elf_shent->sh_name) == 0) {
			pr_debug("[ztex] found .plt in %s\n",
				 kbasename(filepath));
			pr_debug("[hsuck] start: %#0llx, size: %#0llx\n",
				 elf_shent->sh_addr, elf_shent->sh_size);
			proc_info->plt_start = elf_shent->sh_addr;
			proc_info->plt_size = elf_shent->sh_size;
			proc_info->plt_found = 1;
			continue;
		}
		if (strcmp(".strtab", shstrtab + elf_shent->sh_name) == 0) {
			strtab = elf_fetch_tab(file, elf_shent);
			if (!strtab) {
				pr_err("[ztex] cannot found .strtab in %s\n",
				       kbasename(filepath));
			}
			pr_debug("[hsuck] found .strtab in %s\n",
				 kbasename(filepath));
			continue;
		}
		if (strcmp(".symtab", shstrtab + elf_shent->sh_name) == 0) {
			symtab = elf_fetch_tab(file, elf_shent);
			if (!symtab) {
				pr_err("[ztex] cannot found .symtab in %s\n",
				       kbasename(filepath));
			}
			pr_debug("[ztex] found .symtab in %s\n",
				 kbasename(filepath));
			elf_shsymtab = elf_shent;
			continue;
		}
		if (strcmp(".dynstr", shstrtab + elf_shent->sh_name) == 0) {
			dynstr = elf_fetch_tab(file, elf_shent);
			if (!dynstr) {
				pr_err("[hsuck] cannot found dynstr in %s\n",
				       kbasename(filepath));
			}
			pr_debug("[hsuck] found .dynstr in %s\n",
				 kbasename(filepath));
			continue;
		}
		if (strcmp(".dynamic", shstrtab + elf_shent->sh_name) == 0) {
			dynamic = elf_fetch_tab(file, elf_shent);
			if (!dynamic) {
				pr_err("[hsuck] cannot found dynamic in %s\n",
				       kbasename(filepath));
			}
			pr_debug("[hsuck] found .dynamic in %s\n",
				 kbasename(filepath));
			elf_shdynamic = elf_shent;
			continue;
		}
	}

	sym = elf_get_funcsym(elf_shsymtab, symtab, strtab, TERMINATE_FUNCTION);
	if (!sym) {
		pr_err("[ztex] fail to find the symbol of the terminate function," TERMINATE_FUNCTION
		       "\n");
		htable->elf_entry_found = 0;
		goto fetching_so;
	}
	htable->elf_entry_found = 1;
	htable->elf_entry = sym->st_value;
	pr_debug("[ztex] the terminate function address: 0x%lx\n",
		 htable->elf_entry);

	sym = elf_get_funcsym(elf_shsymtab, symtab, strtab, "_start");
	if (!sym) {
		pr_err("[ztex] fail to find the symbol of the terminate function, _start\n");
		htable->start = 0;
		goto fetching_so;
	}
	htable->start = sym->st_value;
	pr_debug("[ztex] the terminate function (_start) address: 0x%lx\n",
		 htable->start);

	sym = elf_get_funcsym(elf_shsymtab, symtab, strtab, "child_main");
	if (!sym) {
		pr_err("[ztex] fail to find the symbol of the terminate function, child_main\n");
		htable->child_main = 0;
		goto fetching_so;
	}
	htable->child_main = sym->st_value;
	pr_debug("[ztex] the terminate function (child_main) address: 0x%lx\n",
		 htable->start);

fetching_so:
	htable->is_static = elf_ex.e_type != ET_DYN ? 1 : 0;
	/* if (!htable->is_static) */
	elf_get_so(elf_shdynamic, dynamic, dynstr, htable);

	kfree(strtab);
	kfree(symtab);
	kfree(dynstr);
	kfree(dynamic);
out_free_strtab:
	kfree(shstrtab);
out_free_shdata:
	kfree(elf_shdata);

out:
	if (file)
		filp_close(file, NULL);

	return syscall_NR == __NR_execve ? orig_execve(pt_regs) :
					   orig_execveat(pt_regs);
}

static void copy_table(table_t *ptable, table_t *ctable)
{
	ctable->address     = ptable->address;
	ctable->size        = ptable->size;
	ctable->header      = ptable->header;
	ctable->hdrsz       = ptable->hdrsz;
	ctable->state_cache = ptable->state_cache;
	ctable->num_caches  = ptable->num_caches;
	/* ctable->name        = get_task_full_comm(current); */

	return;
}

asmlinkage long hacked_clone(const struct pt_regs *pt_regs)
{
	char *parent_name, *child_name;
	int bkt;
	long retval;
	struct hash_table *pphtable, *cphtable;
	struct so_info *cur, *item;
	struct task_struct *t;
	table_t *ptable, *ctable;

	parent_name = get_task_full_comm(current);
	if (delta_app_inlist(kbasename(parent_name))) {
		pr_debug("[vicky] syscall `clone` is hooked, "
			 "%s(%d)\n",
			 kbasename(parent_name), task_pid_nr(current));
		syscall_protection();
	}

	mutex_lock(&sandbox_mutex);
	retval = orig_clone(pt_regs);
	/* task_struct of child */
	t = pid_task(find_vpid(retval), PIDTYPE_PID);
	if (!t) {
		pr_err("[hsuck] can not find child task by pid(%ld)\n", retval);
		goto out;
	}

	child_name = get_task_full_comm(t);
	if (delta_app_inlist(kbasename(parent_name)) &&
	    !strcmp(kbasename(parent_name), kbasename(child_name))) {
		/* Find hash table of parent */
		if (!(pphtable = search_htable(kbasename(parent_name),
					       task_pid_nr(current)))) {
			pr_err("[hsuck] %s, %d: %s, %d htable not found\n",
			       __FUNCTION__, __LINE__, kbasename(parent_name),
			       task_pid_nr(current));
			goto out;
		}
		/* Create hash table for children */
		if (create_htable(kbasename(child_name), task_pid_nr(t),
				  false) == -1) {
			pr_err("[hsuck] %d: fuck", __LINE__);
			goto out;
		}
		if (!(cphtable = search_htable(kbasename(child_name),
					       task_pid_nr(t)))) {
			pr_err("[hsuck] %s, %d: %s, %d htable not found\n",
			       __FUNCTION__, __LINE__, kbasename(child_name),
			       task_pid_nr(t));
			goto out;
		}
		/* Insert entries of parent's table to children's table */
		pr_debug("[hsuck] copying so_info from %d to %d\n",
			 task_pid_nr(current), task_pid_nr(t));
		hash_for_each (pphtable->htable, bkt, cur, node) {
			insert_item(cphtable, cur->name);
			pr_debug("[hsuck] item name=%s\n", cur->name);
			if (!(item = search_item(cphtable, cur->name))) {
				pr_err("[hsuck] %s:%d %s item not found\n",
				       __FUNCTION__, __LINE__, cur->name);
				goto out;
			}
			item->eh_frame_size  = cur->eh_frame_size;
			item->eh_frame_start = cur->eh_frame_start;
			item->eh_frame_found = cur->eh_frame_found;
			item->ehframe        = cur->ehframe;
			item->plt_size       = cur->plt_size;
			item->plt_start      = cur->plt_start;
			item->plt_found      = cur->plt_found;
		}

		if (!pphtable->root_table)
			goto copy_htable;

		pr_debug("[hsuck] copying unwind_table from %d to %d\n",
			 task_pid_nr(current), task_pid_nr(t));
		cphtable->root_table = kmalloc(sizeof(table_t), GFP_KERNEL);
		if (!cphtable->root_table) {
			pr_err("[hsuck] %s:%d buffer allocation failed\n",
			       __FUNCTION__, __LINE__);
			goto out;
		}
		memset(cphtable->root_table, 0, sizeof(table_t));

		copy_table(pphtable->root_table, cphtable->root_table);
		cphtable->root_table->next = cphtable->root_table;
		cphtable->root_table->prev = cphtable->root_table;

		if (!(item = search_item(cphtable,
					 pphtable->root_table->info->name))) {
			pr_err("[hsuck] %s:%d %s item not found\n",
			       __FUNCTION__, __LINE__, cur->name);
			goto out;
		}
		cphtable->root_table->info = item;

		ptable = pphtable->root_table->next;
		ctable = cphtable->root_table;
		while (ptable && ptable != pphtable->root_table) {
			if (!(item = search_item(cphtable,
						 ptable->info->name))) {
				pr_err("[hsuck] %s:%d %s item not found\n",
				       __FUNCTION__, __LINE__, cur->name);
				goto out;
			}
			ctable = unwind_add_table(cphtable, item);
			copy_table(ptable, ctable);
			ptable = ptable->next;
		}

copy_htable:
		cphtable->rpath           = pphtable->rpath;
		cphtable->elf_entry       = pphtable->elf_entry;
		cphtable->clone_entry     = pphtable->clone_entry;
		cphtable->child_main      = pphtable->child_main;
		cphtable->elf_entry_found = pphtable->elf_entry_found;
		cphtable->cntr            = pphtable->cntr;

		/* pr_debug("[hsuck] cntr: %s, %d\n", pphtable->name, */
		/*	atomic_inc_return(pphtable->cntr)); */
		atomic_inc(pphtable->cntr);
		pr_debug("[hsuck] copy metadata successfully from %d to %d\n",
			 task_pid_nr(current), task_pid_nr(t));
	}
out:
	mutex_unlock(&sandbox_mutex);
	kfree(parent_name);
	kfree(child_name);

	return retval;
}

static void release_partial(struct hash_table **phtab)
{
	int bkt;
	struct so_info *scur;
	struct hlist_node *htmp = NULL;
	table_t *tmp, *cur;
	struct hash_table *phtable = *phtab;

	// free unwind_table
	pr_debug("[hsuck] freeing unwind_table...\n");
	cur = phtable->root_table;
	if (!cur)
		goto out_free_htable;
	do {
		tmp = cur;
		cur = cur->next;
		pr_debug("[hsuck] (%s, %d)\n", tmp->info->name, phtable->pid);
		kfree(tmp);
	} while (cur && cur != phtable->root_table);
	(*phtab)->root_table = NULL;

out_free_htable:
	// free so_info
	pr_debug("[hsuck] freeing so_info...\n");
	if (!hash_empty(phtable->htable))
		hash_for_each_safe (phtable->htable, bkt, htmp, scur, node) {
			pr_debug("[hsuck] (%s, %d)\n", scur->name,
				 phtable->pid);
			hash_del(&scur->node);
			kfree(scur->name);
			kfree(scur);
		}

	// free hash_table
	hash_del(&phtable->node);
	kfree(phtable->name);
	kfree(phtable);
	(*phtab) = NULL;
	return;
}

static void release_all(struct hash_table **phtab)
{
	int i, bkt;
	struct so_info *scur;
	struct hlist_node *htmp = NULL;
	table_t *tmp, *cur;
	struct hash_table *phtable = *phtab;

	// free unwind_table
	pr_info("[hsuck] freeing unwind_table...\n");
	cur = phtable->root_table;
	if (!cur)
		goto out_free_htable;
	do {
		tmp = cur;
		cur = cur->next;
		kfree(tmp->header);
		pr_info("[hsuck] (%s, %d) cachesz=%u\n", tmp->info->name,
			 phtable->pid, tmp->num_caches);
		for (i = 0; i < tmp->num_caches; ++i)
			kfree(tmp->state_cache[i]);
		kfree(tmp->state_cache);
		kfree(tmp);
	} while (cur && cur != phtable->root_table);
	(*phtab)->root_table = NULL;

out_free_htable:
	pr_info("[hsuck] freeing so_info...\n");
	// free so_info
	if (!hash_empty(phtable->htable))
		hash_for_each_safe (phtable->htable, bkt, htmp, scur, node) {
			pr_info("[hsuck] (%s, %d)\n", scur->name,
				 phtable->pid);
			hash_del(&scur->node);
			kfree(scur->ehframe);
			kfree(scur->name);
			kfree(scur);
		}
	hash_del(&phtable->node);
	kfree(phtable->name);
	kfree(phtable->rpath);
	kfree(phtable->cntr);
	kfree(phtable);
	(*phtab) = NULL;

	return;
}

static void release_memory(void)
{
	int retval;
	char *filepath = get_task_full_comm(current);
	struct hash_table *phtable =
		search_htable(kbasename(filepath), task_pid_nr(current));

	pr_debug("[hsuck] release metadata for (%s, %d)\n", kbasename(filepath),
		 task_pid_nr(current));
	if (!phtable) {
		pr_err("[hsuck] %s, L%d:  %s(%d) htable not found\n",
		       __FUNCTION__, __LINE__, kbasename(filepath),
		       task_pid_nr(current));
		goto out;
	}

	if (!phtable->cntr) {
		pr_err("[hsuck] %s:%d %s:%d cntr not found\n", __FUNCTION__,
		       __LINE__, kbasename(filepath), task_pid_nr(current));
		goto out;
	}

	retval = atomic_dec_return(phtable->cntr);
	pr_debug("[hsuck] cntr: %s(%d), %d\n", phtable->name, phtable->pid,
		 retval);

	if (!retval) {
		release_all(&phtable);
	} else {
		release_partial(&phtable);
	}
out:
	kfree(filepath);	
	
	return;
}

asmlinkage long hacked_exit_family(const struct pt_regs *pt_regs)
{
	unsigned int syscall_NR = pt_regs->user_regs.regs[8];

	if (delta_app_inlist(current->comm)) {
		pr_info("[vicky] syscall `exit(_group)` is hooked, "
			 "%s(%d)\n",
			 current->comm, task_pid_nr(current));
		release_memory();
	}

	return syscall_NR == __NR_exit ? orig_exit(pt_regs) :
					 orig_exit_group(pt_regs);
}

static int __hook_syscall(void)
{
	/* File system related */
	orig_openat     = (sys_call_t)__sys_call_table[__NR_openat];
	orig_read       = (sys_call_t)__sys_call_table[__NR_read];
	orig_write      = (sys_call_t)__sys_call_table[__NR_write];
	orig_readv      = (sys_call_t)__sys_call_table[__NR_readv];
	orig_writev     = (sys_call_t)__sys_call_table[__NR_writev];
	orig_sendfile   = (sys_call_t)__sys_call_table[__NR_sendfile];
	orig_recvfrom   = (sys_call_t)__sys_call_table[__NR_recvfrom];
	/* Arbitrary Code Execution */
	orig_execve     = (sys_call_t)__sys_call_table[__NR_execve];
	orig_execveat   = (sys_call_t)__sys_call_table[__NR_execveat];
	orig_clone      = (sys_call_t)__sys_call_table[__NR_clone];
	/* Memory Permissions */
	orig_mprotect   = (sys_call_t)__sys_call_table[__NR_mprotect];
	orig_mmap       = (sys_call_t)__sys_call_table[__NR_mmap];
	orig_mremap     = (sys_call_t)__sys_call_table[__NR_mremap];
	/* Networking */
	orig_socket     = (sys_call_t)__sys_call_table[__NR_socket];
	orig_bind       = (sys_call_t)__sys_call_table[__NR_bind];
	orig_connect    = (sys_call_t)__sys_call_table[__NR_connect];
	orig_listen     = (sys_call_t)__sys_call_table[__NR_listen];
	orig_accept     = (sys_call_t)__sys_call_table[__NR_accept];
	orig_accept4    = (sys_call_t)__sys_call_table[__NR_accept4];
	/* Others */
	orig_exit       = (sys_call_t)__sys_call_table[__NR_exit];
	orig_exit_group = (sys_call_t)__sys_call_table[__NR_exit_group];

	/* File system related */
	__sys_call_table[__NR_openat]     = (unsigned long)hacked_syscall;
	__sys_call_table[__NR_read]       = (unsigned long)hacked_syscall;
	__sys_call_table[__NR_write]      = (unsigned long)hacked_syscall;
	__sys_call_table[__NR_readv]      = (unsigned long)hacked_syscall;
	__sys_call_table[__NR_writev]     = (unsigned long)hacked_syscall;
	__sys_call_table[__NR_sendfile]   = (unsigned long)hacked_syscall;
	__sys_call_table[__NR_recvfrom]   = (unsigned long)hacked_syscall;
	/* Arbitrary Code Execution */
	__sys_call_table[__NR_execve]     = (unsigned long)hacked_execve_family;
	__sys_call_table[__NR_execveat]   = (unsigned long)hacked_execve_family;
	__sys_call_table[__NR_clone]      = (unsigned long)hacked_clone;
	/* Memory Permissions */
	__sys_call_table[__NR_mprotect]   = (unsigned long)hacked_syscall;
	__sys_call_table[__NR_mmap]       = (unsigned long)hacked_syscall;
	__sys_call_table[__NR_mremap]     = (unsigned long)hacked_syscall;
	/* Networking */
	__sys_call_table[__NR_socket]     = (unsigned long)hacked_syscall;
	__sys_call_table[__NR_bind]       = (unsigned long)hacked_syscall;
	__sys_call_table[__NR_connect]    = (unsigned long)hacked_syscall;
	__sys_call_table[__NR_listen]     = (unsigned long)hacked_syscall;
	__sys_call_table[__NR_accept]     = (unsigned long)hacked_syscall;
	__sys_call_table[__NR_accept4]    = (unsigned long)hacked_syscall;
	/* Others */
	__sys_call_table[__NR_exit]       = (unsigned long)hacked_exit_family;
	__sys_call_table[__NR_exit_group] = (unsigned long)hacked_exit_family;
	pr_debug("[ztex] success to overwrite __sys_call_table\n");
	return 0;
}

static void __unhook_syscall(void)
{
	/* File system related */
	__sys_call_table[__NR_openat]     = (unsigned long)orig_openat;
	__sys_call_table[__NR_read]       = (unsigned long)orig_read;
	__sys_call_table[__NR_write]      = (unsigned long)orig_write;
	__sys_call_table[__NR_readv]      = (unsigned long)orig_readv;
	__sys_call_table[__NR_writev]     = (unsigned long)orig_writev;
	__sys_call_table[__NR_sendfile]   = (unsigned long)orig_sendfile;
	__sys_call_table[__NR_recvfrom]   = (unsigned long)orig_recvfrom;
	/* Arbitrary Code Execution */
	__sys_call_table[__NR_execve]     = (unsigned long)orig_execve;
	__sys_call_table[__NR_execveat]   = (unsigned long)orig_execveat;
	__sys_call_table[__NR_clone]      = (unsigned long)orig_clone;
	/* Memory Permissions */
	__sys_call_table[__NR_mprotect]   = (unsigned long)orig_mprotect;
	__sys_call_table[__NR_mmap]       = (unsigned long)orig_mmap;
	__sys_call_table[__NR_mremap]     = (unsigned long)orig_mremap;
	/* Networking */
	__sys_call_table[__NR_socket]     = (unsigned long)orig_socket;
	__sys_call_table[__NR_bind]       = (unsigned long)orig_bind;
	__sys_call_table[__NR_connect]    = (unsigned long)orig_connect;
	__sys_call_table[__NR_listen]     = (unsigned long)orig_listen;
	__sys_call_table[__NR_accept]     = (unsigned long)orig_accept;
	__sys_call_table[__NR_accept4]    = (unsigned long)orig_accept4;
	/* Others */
	__sys_call_table[__NR_exit]       = (unsigned long)orig_exit;
	__sys_call_table[__NR_exit_group] = (unsigned long)orig_exit_group;
}

static int hook_syscall(void)
{
	int ret = 0;

	spin_lock(&sandbox_spinlock);
	if (syscall_hooked == 0) {
		pr_debug("[ztex] try to overwrite __sys_calltable\n");
		ret = __hook_syscall();
		syscall_hooked = 1;
	} else if (syscall_hooked == 1) {
		__unhook_syscall();
		syscall_hooked = 0;
	}
	spin_unlock(&sandbox_spinlock);

	return ret;
}

static int get_symbol_and_unprot_mem(void)
{
	unsigned long start_rodata, init_begin, section_size = 0;

	pr_debug("[vicky] in function get_symbol_and_uprot_mem\n");

	__sys_call_table =
		(unsigned long *)__kallsyms_lookup_name("sys_call_table");
	if (!__sys_call_table)
		return -EFAULT;

	update_mapping_prot =
		(void *)__kallsyms_lookup_name("update_mapping_prot");
	start_rodata = (unsigned long)__kallsyms_lookup_name("__start_rodata");
	init_begin = (unsigned long)__kallsyms_lookup_name("__init_begin");
	section_size = init_begin - start_rodata;

	update_mapping_prot(__pa_symbol(start_rodata),
			    (unsigned long)start_rodata, section_size,
			    PAGE_KERNEL);
	pr_debug("[vicky] successfully update syscall table protection.\n");

	return 0;
}

static int rootkit_open(struct inode *inode, struct file *filp)
{
	pr_debug("[hsuck] %s\n", __FUNCTION__);
	return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp)
{
	pr_debug("[hsuck] %s\n", __FUNCTION__);
	return 0;
}

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
			  unsigned long arg)
{
	pr_debug("[hsuck] %s\n", __FUNCTION__);
	/* switch (ioctl) { */
	/* case IOCTL_DISABLE_UNWIND: */
	/*	pr_debug("[vicky] Unwind is disabled\n"); */
	/*	memset(hook_app, 0, MAX_NAME); */
	/*	memset(hook_app2, 0, MAX_NAME); */
	/*	memset(hook_app3, 0, MAX_NAME); */
	/*	break; */
	/* case IOCTL_ENABLE_UNWIND: */
	/*	pr_debug("[vicky] Unwind is enabled\n"); */
	/*	strncpy(hook_app, "test1", 5); */
	/*	strncpy(hook_app2, "httpd", 5); */
	/*	strncpy(hook_app3, "netserver", 9); */
	/*	break; */
	/* default: */
	/*	pr_debug("[vicky] ioctl illegal command\n"); */
	/*	break; */
	/* } */
	return 0;
}

struct file_operations fops = {
	open: rootkit_open,
	unlocked_ioctl: rootkit_ioctl,
	release: rootkit_release,
	owner: THIS_MODULE
};

static struct miscdevice sandbox = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sandbox",
	.fops = &fops,
	.mode = 0664,
};

static int __init sandbox_init(void)
{
	int ret;

	if ((ret = misc_register(&sandbox)) < 0)
		pr_err("[hsuck] misc_register failed, ret = %d\n", ret);

	pr_info("[vicky] successfully init %s\n", OURMODNAME);
	spin_lock_init(&sandbox_spinlock);
	mutex_init(&sandbox_mutex);

	register_kprobe(&kp);
	__kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);

	get_symbol_and_unprot_mem();
	ret = hook_syscall();
	if (ret < 0) {
		pr_err("[vicky] fail to hook syscall\n");
	}
	hash_init(proc_htable);

	__find_vma_prev = (void *)__kallsyms_lookup_name("find_vma_prev");
	__find_get_task_by_vpid =
		(void *)__kallsyms_lookup_name("find_get_task_by_vpid");

	return 0;
}

static void __exit sandbox_exit(void)
{
	int bkt0, bkt1;
	struct hash_table *phtable;
	struct so_info *cur;
	struct hlist_node *tmp = NULL;

	spin_lock(&sandbox_spinlock);
	if (syscall_hooked == 1) {
		__unhook_syscall();
		syscall_hooked = 0;
	}
	spin_unlock(&sandbox_spinlock);

	hash_for_each (proc_htable, bkt0, phtable, node) {
		pr_info("[hsuck] (%s, %d)\n", phtable->name, phtable->pid);
		deinit_unwind_table(&phtable, 1);
		hash_for_each_safe (phtable->htable, bkt1, tmp, cur, node) {
			pr_info("[hsuck] (%s)\n", cur->name);
			hash_del(&cur->node);
			kfree(cur->ehframe);
			kfree(cur->name);
			kfree(cur);
		}
		hash_del(&phtable->node);
		kfree(phtable->name);
		kfree(phtable->rpath);
		kfree(phtable->cntr);
		kfree(phtable);
	}

	pr_debug("[vicky] %s: removed\n", OURMODNAME);
	misc_deregister(&sandbox);
}

module_init(sandbox_init);
module_exit(sandbox_exit);

MODULE_AUTHOR("Tony Liu <ztex030640417@gmail.com>");
MODULE_DESCRIPTION("Delta sandbox system call protection");
MODULE_LICENSE("GPL");
MODULE_VERSION(SANDBOX_VERSION);
