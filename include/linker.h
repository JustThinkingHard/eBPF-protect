#ifndef __LINKER_H__
#define __LINKER_H__

#define READ_SZ 512
#define PATH_MAX 4096

typedef struct {
    __u32 pid;
    __u32 tgid;
    __u32 fd;
    __u8 comm[16];
    __u64 size;
    __u8 data[READ_SZ];
    __u64 inode;
} link_t;

#endif /* __LINKER_H__ */