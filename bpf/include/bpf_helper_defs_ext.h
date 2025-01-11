/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

/*
 * Note: when compiling kmesh, the helper function IDs listed in this
 * file will be updated based on the file "/usr/include/linux/bpf.h"
 * in the compilation environment. In addition, newly developed helper
 * functions will also be added here in the future.
 *
 * By default, these IDs are in the 5.10 kernel with kmesh kernel patches.
 */

static int (*bpf_km_strnstr)(
    struct bpf_sock_addr *ctx, const char *key, int key_sz, const char *subptr, int subptr_sz) = (void *)163;
static int (*bpf_km_strncmp)(
    struct bpf_sock_addr *ctx, const char *key, int key_sz, const char *subptr, int subptr_sz) = (void *)164;
static long (*bpf_parse_header_msg)(struct bpf_sock_addr *ctx) = (void *)165;
