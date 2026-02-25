// SPDX-License-Identifier: GPL-2.0
// AssetsWarden eBPF LSM program
// Hooks: inode_unlink, inode_rmdir, inode_rename
// Strategy: inode-based comparison (no string path parsing in kernel)

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// ------------------------------------------------------------------
// BPF Maps
// ------------------------------------------------------------------

// config_map: 受保护目录的 inode 信息
// key: protected dir inode number (u64)
// value: device number (u64)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u64);
} config_map SEC(".maps");

// uid_filter_map: 受监控的 uid 集合
// key: uid (u32), value: 1 (sentinel)
// 空表 = 监控所有用户
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} uid_filter_map SEC(".maps");

// uid_filter_enabled: 是否启用 uid 过滤
// key: 0, value: 1 = 启用
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} uid_filter_enabled SEC(".maps");

// events: ring buffer，向用户态发送拦截事件
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 1024); // 4MB
} events SEC(".maps");

// ------------------------------------------------------------------
// Event structure (shared with userspace via Go codegen)
// ------------------------------------------------------------------

#define TASK_COMM_LEN 16

struct warden_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u8  op;        // 0=unlink, 1=rmdir, 2=rename
    __u8  _pad[3];
    __u64 ino;       // 目标文件 inode
    __u64 dev;       // 设备号
    __u64 dir_ino;   // 父目录 inode
    __u64 dest_ino;  // (rename) 目标 inode
    __u64 dest_dir_ino; // (rename) 目标父目录 inode
    char  comm[TASK_COMM_LEN];
};

// ------------------------------------------------------------------
// Helper: 向上遍历 dentry 链，检查是否有祖先 inode 在 config_map 中
// 返回值: 1 = 命中保护目录, 0 = 未命中
// ------------------------------------------------------------------
static __always_inline int is_protected(struct dentry *dentry, __u64 dev) {
    struct dentry *cur = dentry;

#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (!cur)
            break;

        struct inode *inode = BPF_CORE_READ(cur, d_inode);
        if (!inode)
            break;

        __u64 ino = BPF_CORE_READ(inode, i_ino);
        __u64 *stored_dev = bpf_map_lookup_elem(&config_map, &ino);
        if (stored_dev && *stored_dev == dev) {
            return 1;
        }

        struct dentry *parent = BPF_CORE_READ(cur, d_parent);
        if (parent == cur)
            break; // 到达根节点

        cur = parent;
    }
    return 0;
}

// Helper: 获取 dentry 所在设备号
static __always_inline __u64 get_dev(struct dentry *dentry) {
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode)
        return 0;
    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb)
        return 0;
    return BPF_CORE_READ(sb, s_dev);
}

// Helper: uid 过滤. 返回 1 表示"应该拦截此 uid"
static __always_inline int should_monitor_uid(__u32 uid) {
    __u32 key = 0;
    __u8 *enabled = bpf_map_lookup_elem(&uid_filter_enabled, &key);
    if (!enabled || *enabled == 0) {
        // uid 过滤未启用 → 监控所有 uid
        return 1;
    }
    // 启用了 uid 过滤 → 只拦截在 uid_filter_map 中的 uid
    __u8 *v = bpf_map_lookup_elem(&uid_filter_map, &uid);
    return (v != NULL) ? 1 : 0;
}

// Helper: 发送事件到 ring buffer（不阻塞，若满则丢弃）
static __always_inline void emit_event(__u8 op,
                                       __u32 pid, __u32 uid,
                                       __u64 ino, __u64 dev, __u64 dir_ino,
                                       __u64 dest_ino, __u64 dest_dir_ino) {
    struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->timestamp     = bpf_ktime_get_ns();
    e->pid           = pid;
    e->uid           = uid;
    e->op            = op;
    e->ino           = ino;
    e->dev           = dev;
    e->dir_ino       = dir_ino;
    e->dest_ino      = dest_ino;
    e->dest_dir_ino  = dest_dir_ino;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}

// ------------------------------------------------------------------
// LSM Hook: inode_unlink
// ------------------------------------------------------------------
SEC("lsm/inode_unlink")
int BPF_PROG(warden_unlink, struct inode *dir, struct dentry *dentry) {
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (!should_monitor_uid(uid))
        return 0;

    __u64 dev = get_dev(dentry);
    if (!is_protected(dentry, dev))
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    __u64 dir_ino = BPF_CORE_READ(dir, i_ino);

    emit_event(0, pid, uid, ino, dev, dir_ino, 0, 0);
    return -EPERM;
}

// ------------------------------------------------------------------
// LSM Hook: inode_rmdir
// ------------------------------------------------------------------
SEC("lsm/inode_rmdir")
int BPF_PROG(warden_rmdir, struct inode *dir, struct dentry *dentry) {
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (!should_monitor_uid(uid))
        return 0;

    __u64 dev = get_dev(dentry);
    if (!is_protected(dentry, dev))
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    __u64 dir_ino = BPF_CORE_READ(dir, i_ino);

    emit_event(1, pid, uid, ino, dev, dir_ino, 0, 0);
    return -EPERM;
}

// ------------------------------------------------------------------
// LSM Hook: inode_rename
// ------------------------------------------------------------------
SEC("lsm/inode_rename")
int BPF_PROG(warden_rename,
             struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry,
             unsigned int flags) {
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (!should_monitor_uid(uid))
        return 0;

    __u64 dev = get_dev(old_dentry);

    // 拦截：源路径在保护目录下，或目标路径在保护目录下（移出也算）
    int src_protected  = is_protected(old_dentry, dev);
    int dest_protected = 0;
    if (new_dentry) {
        __u64 dest_dev = get_dev(new_dentry);
        dest_protected = is_protected(new_dentry, dest_dev);
    }

    if (!src_protected && !dest_protected)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 src_ino      = BPF_CORE_READ(old_dentry, d_inode, i_ino);
    __u64 src_dir_ino  = BPF_CORE_READ(old_dir, i_ino);
    __u64 dest_ino     = new_dentry ? BPF_CORE_READ(new_dentry, d_inode, i_ino) : 0;
    __u64 dest_dir_ino = BPF_CORE_READ(new_dir, i_ino);

    emit_event(2, pid, uid, src_ino, dev, src_dir_ino, dest_ino, dest_dir_ino);
    return -EPERM;
}
