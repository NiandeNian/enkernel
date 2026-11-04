#ifndef MEM_HIDE_H
#define MEM_HIDE_H

#include <linux/compiler_types.h>
#include <linux/types.h>

long mem_hide_process(void __user *arg);
long mem_hide_path(void __user *arg);
long mem_hide_list(void __user *arg);

int mem_hide_init(void);
void mem_hide_exit(void);

#endif /* MEM_HIDE_H */
