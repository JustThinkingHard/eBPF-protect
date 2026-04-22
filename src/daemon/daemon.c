#include <bpf/libbpf.h>
#include "../../include/check.skel.h"
#include <sys/epoll.h>
#include "../../include/linker.h"
#include <signal.h>
#include <math.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/inotify.h>
#define _GNU_SOURCE
#include <stdio.h>

struct check_bpf *skel = NULL;
volatile sig_atomic_t stop = 0;

void save_blacklist(struct bpf_map *map, link_t *data)
{
    FILE *fd = fopen("blacklist.txt", "a");

    if (!fd)
        return;

    fprintf(fd, "%llu %s\n", data->inode, data->comm);
    fclose(fd);
}

void update_blacklist(uint64_t inodes[10240], struct bpf_map *map)
{
    FILE *fd = fopen("blacklist.txt", "r");
    char *file = NULL;
    __u64 list_inode[10240];
    int pos = 0;
    int present = 0;
    __u64 key;
    size_t r_size = 0;
    __u8 val = 1;

    if (!fd) {
        return;
    }
    while (pos < 10240 && getline(&file, &r_size, fd) != -1) {
        if (file[strlen(file) - 1] == '\n')
            file[strlen(file) - 1] = '\0';
        sscanf(file, "%llu", &list_inode[pos]);
        pos++;
    }
    for (int i = 0; inodes[i] != 0; i++) {
        present = 0;
        for (int y = 0; y != pos; y++) {
            if (inodes[i] == list_inode[y]) {
                present = 1;
                break;
            }
        }
        if (present == 0) {
            key = inodes[i];
            bpf_map__delete_elem(map, &key, sizeof(__u64), 0);
        }
    }

    for (int i = 0; i != pos; i++) {
        key = list_inode[i];
        bpf_map__update_elem(map, &key, sizeof(__u64), &val, sizeof(__u8), 0);
    }
    free(file);
    fclose(fd);
    printf("Blacklist is updated\n");
}

void update_whitelist(uint64_t inodes[10240], struct bpf_map *map)
{
    FILE *fd = fopen("whitelist.txt", "r");
    char *file = NULL;
    __u64 list_inode[10240];
    int pos = 0;
    int present = 0;
    __u64 key;
    size_t r_size = 0;
    __u8 val = 1;
    struct stat s;

    if (!fd) {
        return;
    }
    while (pos < 10240 && getline(&file, &r_size, fd) != -1) {
        file[strcspn(file, "\r\n")] = 0;
        if (!access(file, F_OK)) {
            if (stat(file, &s))
                printf("[-] STAT FAILED for: %s\n", file);
            else {
                list_inode[pos] = s.st_ino;
            }
        }
        pos++;
    }
    for (int i = 0; inodes[i] != 0; i++) {
        present = 0;
        for (int y = 0; y != pos; y++) {
            if (inodes[i] == list_inode[y]) {
                present = 1;
                break;
            }
        }
        if (present == 0) {
            key = inodes[i];
            bpf_map__delete_elem(map, &key, sizeof(__u64), 0);
        }
    }

    for (int i = 0; i != pos; i++) {
        key = list_inode[i];
        bpf_map__update_elem(map, &key, sizeof(__u64), &val, sizeof(__u8), 0);
    }
    free(file);
    fclose(fd);
    printf("Whitelist is updated\n");
}

void update_list(struct bpf_map *map, int color)
{
    uint64_t next_key;
    uint64_t key;
    int ret = bpf_map__get_next_key(map, NULL, &next_key, sizeof(uint64_t));
    uint64_t inodes[10240];
    int i = 0;

    while (ret != -ENOENT) {
        inodes[i] = key;

        key = next_key;
        i++;
        ret = bpf_map__get_next_key(map, &key, &next_key, sizeof(uint64_t));
    }
    inodes[i] = 0;

    if (color)
        update_whitelist(inodes, map);
    else
        update_blacklist(inodes, map);
}

double calculate_shannon_entropy(uint8_t *data, size_t len) {
    int freq[READ_SZ] = {0};
    double entropy = 0.0;

    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }

    for (int i = 0; i < READ_SZ; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / (double)len;

            entropy -= p * log2(p);
        }
    }

    return entropy;
}

int entropy_calculus(void *ctx, void *data, size_t data_sz)
{
    link_t *data_check = (link_t *)data;

    double entropy = calculate_shannon_entropy(data_check->data, READ_SZ);
    if (entropy >= 7.3) {
        printf("PID %d, command %s, fd %d\n", data_check->pid, data_check->comm, data_check->fd);
        save_blacklist(skel->maps.blacklist, data_check);
    }
    return 0;
}

void start()
{
    skel = check_bpf__open_and_load();
    check_bpf__attach(skel);
}

void stopping(int dummy)
{
    stop = 1;
}

void daemonize()
{
    int efd, fd,  wd_whitelist, wd_blacklist;
    struct epoll_event ev, ev_rb, events[10];
    struct inotify_event *event_inot;
    struct ring_buffer *rb;
    int rb_epoll_fd;
    int sz_events;
    char tmp[4096];

    fd = inotify_init();
    if (fd < 0)
        goto error;
    wd_whitelist = inotify_add_watch(fd, "whitelist.txt", IN_MODIFY);
    wd_blacklist = inotify_add_watch(fd, "blacklist.txt", IN_MODIFY);

    if (wd_whitelist < 0 || wd_blacklist < 0) {
        perror("inotify_add_watch failed");
        goto error;
    }

    ev.events = EPOLLIN;
    ev.data.fd = fd;

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), entropy_calculus, NULL, NULL);
    rb_epoll_fd = ring_buffer__epoll_fd(rb);
    ev_rb.events = EPOLLIN;
    ev_rb.data.fd = rb_epoll_fd;

    efd = epoll_create1(0);
    if (efd == -1) {
        printf("Error creating epoll\n");
        return;
    }

    if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) == -1)
        goto error_ctl;
    if (epoll_ctl(efd, EPOLL_CTL_ADD, rb_epoll_fd, &ev_rb) == -1)
        goto error_ctl;

    signal(SIGINT, stopping);
    // Update lists before to make sure modifications have been written
    update_list(skel->maps.whitelist, 1);
    update_list(skel->maps.blacklist, 0);
    printf("[*] ------------------------------- [*] \n");
    printf("eBPF anti-ransomware running !\n");
    printf("[*] ------------------------------- [*] \n");
    while(!stop) {
        sz_events = epoll_wait(efd, events, 10, -1);
        if (sz_events < 0) continue;
        for (int i = 0; i != sz_events; i++) {
            if (events[i].data.fd == rb_epoll_fd)
                ring_buffer__consume(rb);
            else if (events[i].data.fd == fd) {
                read(fd, tmp, sizeof(tmp));
                event_inot = (struct inotify_event *)tmp;
                if (event_inot->wd == wd_whitelist)
                    update_list(skel->maps.whitelist, 1);
                else if (event_inot->wd == wd_blacklist) {
                    update_list(skel->maps.blacklist, 0);
                }
            }
        }
    }
    ring_buffer__free(rb);
    check_bpf__destroy(skel);


error_ctl:
    close(fd);
error:
    close(efd);
    printf("Clean up done, everything is shut down\n");
}

int main(void)
{
    start();
    daemonize();
}