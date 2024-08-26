#ifndef __EBPF_EVM_H__
#define __EBPF_EVM_H__

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/module.h>
#include <linux/evm.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/xattr.h>

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
                              const struct btf_kfunc_id_set *kset);
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

int (*vfs_removexattr)(struct mnt_idmap *, struct dentry *,
	const char *);

int (*__vfs_removexattr)(struct mnt_idmap *, struct dentry *,
	const char *);

ssize_t (*vfs_listxattr)(struct dentry *, char *, size_t);

ssize_t (*vfs_getxattr)(struct mnt_idmap *, struct dentry *,
	const char *, void *, size_t);

ssize_t (*__vfs_getxattr)(struct dentry *, struct inode *,
	const char *, void *, size_t);

int (*__vfs_setxattr_locked)(struct mnt_idmap *, struct dentry *, 
	const char *, const void *, size_t, int, struct inode **);

int (*vfs_setxattr)(struct mnt_idmap *, struct dentry *, const char *,
	const void *, size_t, int);

int (*__vfs_setxattr)(struct mnt_idmap *, struct dentry *,
	struct inode *, const char *, const void *, size_t, int);

int (*__vfs_removexattr_locked)(struct mnt_idmap *, struct dentry *,
	const char *, struct inode **);

enum integrity_status (*evm_verifyxattr)(struct dentry *, const char *,
	void *, size_t);		  

struct ebpf_data {
	struct mnt_id *idmap;
	struct dentry *dentry;
	struct inode *inode;
	const char *name;
	void *value;
	size_t size;
}

