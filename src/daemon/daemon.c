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

int update_map(uint64_t inodes[10240], struct bpf_map *map)
{
    FILE *fd = fopen("whitelist.txt", "r");
    char *file = NULL;
    char tmp[PATH_MAX];
    __u64 list_inode[10240];
    int pos = 0;
    int present = 0;
    __u64 key;
    size_t r_size = 0;
    __u8 val = 1;
    const char *paths[] = {
        "/usr/bin/",
        "/usr/sbin/"
    };
    int size_paths = sizeof(paths) / sizeof(paths[0]);
    struct stat s;

    if (!fd) {
        return -1;
    }
    while (pos < 10240 && getline(&file, &r_size, fd) != -1) {
        if (file[strlen(file) - 1] == '\n')
            file[strlen(file) - 1] = '\0';
        for (int i = 0; i < size_paths; i++) {
            snprintf(tmp, 4096, "%s%s", paths[i], file);
            if (!access(tmp, F_OK)) {
                if (stat(tmp, &s))
                    continue;
                list_inode[pos] = s.st_ino;
                break;
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
}

int update_whitelist(struct bpf_map *map)
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

    update_map(inodes, map);
    return 0;
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
    printf("entropy : %f\n", entropy);
    if (entropy >= 7.3) {
        printf("PID %d, command %s, fd %d\n", data_check->pid, data_check->comm, data_check->fd);
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
    int efd;
    int fd;
    struct epoll_event ev, ev_rb, events[10];
    struct ring_buffer *rb;
    int rb_epoll_fd;
    int sz_events;
    char tmp[4096];

    fd = inotify_init();
    if (!fd)
        goto error;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    inotify_add_watch(fd, "whitelist.txt", IN_MODIFY);


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
    while(!stop) {
        sz_events = epoll_wait(efd, events, 10, -1);
        if (sz_events < 0) continue;
        for (int i = 0; i != sz_events; i++) {
            if (events[i].data.fd == rb_epoll_fd)
                ring_buffer__consume(rb);
            else if (events[i].data.fd == fd) {
                
                update_whitelist(skel->maps.whitelist);
                read(fd, tmp, 4096);
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