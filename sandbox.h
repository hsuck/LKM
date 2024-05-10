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
int traverse_vma(unsigned long);
#endif
