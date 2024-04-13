#ifndef _ASM_SANDBOX_H
#define _ASM_SANDBOX_H
#include <linux/sched.h>
#include <crypto/hash.h>

#define RELEASE_MEMORY(ptr)                 \
	{                                   \
		do {                        \
			if (ptr) {          \
				kfree(ptr); \
				ptr = NULL; \
			}                   \
		} while (0);                \
	}

int delta_app_inlist(const char *);

static int is_all_filled(void);

struct hash_table *search_htable(const char *, const pid_t);
int create_htable(const char *, const pid_t, bool);
void release_htable(const char *, const pid_t, int);

struct so_info *search_item(struct hash_table *, const char *);
int insert_item(struct hash_table *, const char *);


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
#endif
