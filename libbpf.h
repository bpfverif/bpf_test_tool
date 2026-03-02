/* eBPF mini library */
#ifndef __LIBBPF_H
#define __LIBBPF_H

#include <stdlib.h>
#include <stdio.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/bpf.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

#include "filter.h"

long sys_bpf(int cmd, union bpf_attr *uattr, unsigned int size);


int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
		   int max_entries);
int bpf_update_elem(int fd, void *key, void *value, unsigned long long flags);
int bpf_lookup_elem(int fd, void *key, void *value);
int bpf_delete_elem(int fd, void *key);
int bpf_get_next_key(int fd, void *key, void *next_key);

int bpf_prog_load(enum bpf_prog_type prog_type,
		  const struct bpf_insn *insns, int insn_len,
		  const char *license, int kern_version);

int bpf_obj_pin(int fd, const char *pathname);
int bpf_obj_get(const char *pathname);

#define LOG_BUF_SIZE 1<<20
extern char bpf_log_buf[LOG_BUF_SIZE];

/* create RAW socket and bind to interface 'name' */
int open_raw_sock(const char *name);

struct perf_event_attr;
int perf_event_open(struct perf_event_attr *attr, int pid, int cpu,
		    int group_fd, unsigned long flags);
#endif
