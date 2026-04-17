/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include "../../include/vmlinux.h"
#include "../../include/linker.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

const int pid_filter = 0;

#define MAX_ENTRIES 10240


char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, __u64);
 __type(value, __u8);
} whitelist SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int handle_tp(struct trace_event_raw_sys_enter *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    long x = 0;
    void *unsafe = (void*)(ctx->args[1]);
    unsigned long count = ctx->args[2];
    struct task_struct *task = bpf_get_current_task_btf();
    __u64 current_inode;
    link_t *link;
    if (!task) {
        bpf_printk("Coudln't get task_struct\n");
        return 0;
    }
    current_inode = task->mm->exe_file->f_inode->i_ino;
    if (current_inode == 0)
        return 0;
    if (bpf_map_lookup_elem(&whitelist, &current_inode)) {
        return 0;
    }

    link = bpf_ringbuf_reserve(&rb, sizeof(link_t), 0);
    if (!link)
        return 0;
    if (count > READ_SZ * 2) {
        unsafe = unsafe + (count / 2);
    } else if (count < READ_SZ)
        goto error;

    x = bpf_probe_read_user(link->data, READ_SZ, unsafe);

    if (!x) {
        link->pid = pid;
        link->tgid = (__u32)bpf_get_current_pid_tgid();
        link->fd = ctx->args[0];
        if (bpf_get_current_comm(link->comm, TASK_COMM_LEN)) {
            bpf_printk("Failed to get comm\n");
            goto error;
        }
        link->size = count;
        bpf_ringbuf_submit(link, 0);
        bpf_printk("I AM ABOUT TO SEND DATA!\n");
        return 0;
    }
error:
    bpf_ringbuf_discard(link, 0);
    return 0;
}
