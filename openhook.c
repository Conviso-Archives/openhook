#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <asm/pgtable.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

unsigned long cr0;
static unsigned long *sys_call_table;
typedef asmlinkage long (*orig_open_t)(const char *, int, mode_t);
orig_open_t orig_open;

#define START_MEM	PAGE_OFFSET
#define END_MEM		ULONG_MAX

unsigned long *
get_syscall_table_bf(void)
{
	unsigned long *syscall_table;
	unsigned long int i;

	for (i = START_MEM; i < END_MEM; i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
}

/* sys_open hook */
asmlinkage static int
hacked_open(const char __user *pathname, int flags, mode_t mode)
{
	printk(KERN_INFO "sys_open() hook!\n");
	return orig_open(pathname, flags, mode);
}

static inline void
protect_memory(void)
{
	write_cr0(cr0);
}

static inline void
unprotect_memory(void)
{
	write_cr0(cr0 & ~0x00010000);
}

static int __init
syshook_init(void)
{

	sys_call_table = (unsigned long *)get_syscall_table_bf();

	if (!sys_call_table) {
		printk(KERN_INFO "sys_call_table not fount");
		return -1;
	}

	cr0 = read_cr0();

	orig_open = (orig_open_t)sys_call_table[__NR_open];

	unprotect_memory();
	sys_call_table[__NR_open] = (unsigned long)hacked_open;
	protect_memory();


	return 0;
}

static void __exit
syshook_cleanup(void)
{
	if (orig_open) {
		unprotect_memory();
		sys_call_table[__NR_open] = (unsigned long)orig_open;
		protect_memory();
	}

}

module_init(syshook_init);
module_exit(syshook_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Victor Ramos Mello");
MODULE_DESCRIPTION("A sys_call_table hooking example");
