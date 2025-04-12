// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/ptrace.h>  
#include <linux/ipv6.h>


#include "kmesh_common.h"
#include "bpf_log.h"
#include "bpf_common.h"
#include "common.h"

#define MAX_IOVEC 4
#define __MAX_CONCURRENCY   1000
#define INT_LEN                 32
#define CONN_DATA_MAX_SIZE 1024

#define bpf_section(NAME) __attribute__((section(NAME), used))

#define KPROBE(func, type) \
    bpf_section("kprobe/" #func) \
    int bpf_##func(struct type *ctx)

#ifndef bpf_memcpy
#define bpf_memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define READ_KERN(ptr)                                                         \
    ({                                                                         \
        typeof(ptr) _val;                                                      \
        __builtin_memset((void *)&_val, 0, sizeof(_val));                      \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr);                      \
        _val;                                                                  \
    })


struct http_probe_info {
    char data[CONN_DATA_MAX_SIZE];
    __u64 iov_len;
};

typedef __u32 __bitwise __portpair;
typedef __u64 __bitwise __addrpair;

struct sock_common {
	unsigned short		skc_family;
	union {
		__addrpair	skc_addrpair;
		struct {
			__be32	skc_daddr;
			__be32	skc_rcv_saddr;
		};
	};
	union {
		__portpair	skc_portpair;
		struct {
			__be16	skc_dport;
			__u16	skc_num;
		};
	};
	struct in6_addr		skc_v6_daddr;
	struct in6_addr		skc_v6_rcv_saddr;
};

struct sock {
	struct sock_common	__sk_common;
#define sk_family		__sk_common.skc_family
#define sk_v6_daddr		__sk_common.skc_v6_daddr
#define sk_v6_rcv_saddr		__sk_common.skc_v6_rcv_saddr
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 /* 8 KB */);
} map_of_http_probe SEC(".maps");

int bpf_read_kern(void *dst, const void *src, int size)
{
    int ret = 0;
    if (size <= 0) {
        return -1;
    }
    ret = bpf_probe_read_kernel(dst, size, src);
    if (ret != 0) {
        bpf_printk("bpf_read_kern error: %d\n", ret);
        return -1;
    }
    return 0;
}

KPROBE(tcp_sendmsg, pt_regs)
{
    struct sock *l_sock = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *const msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    __u64 iov_len = 0;


    int ret = 0;
    struct http_probe_info *info = NULL;
    struct iovec *iov_ptr = NULL;
    char iov_base[256] = {};
    __u64 tmp_iov_len = 0;

    if (l_sock == NULL) {
        bpf_printk("l_sock is NULL\n");
        return 0;
    }

    if (bpf_core_field_exists(msg->msg_iov))
        iov_ptr = (struct iovec *)READ_KERN(msg->msg_iov);

    if (iov_ptr == NULL) {
        bpf_printk("iov_ptr is NULL\n");
    }

    ret = bpf_probe_read_user(&iov_len, sizeof(__u64), &iov_ptr->iov_len);
    if (ret != 0) {
        bpf_printk("3 ret:%d\n", ret);
        return 0;
    }
    
    if (iov_len < 0) {
        return 0;
    }

    tmp_iov_len = 256;
    ret = bpf_probe_read_user(iov_base, tmp_iov_len, &iov_ptr->iov_base);
    if (ret != 0) {
        bpf_printk("5 ret:%d\n", ret);
        return 0;
    }

    if (__builtin_memcmp(iov_base, "GET", 3) == 0 || 
        __builtin_memcmp(iov_base, "POST", 4) == 0 ||
        __builtin_memcmp(iov_base, "PUT", 3) == 0 ||
        __builtin_memcmp(iov_base, "DELETE", 6) == 0 ||
        __builtin_memcmp(iov_base, "HEAD", 4) == 0 ||
        __builtin_memcmp(iov_base, "OPTIONS", 7) == 0 ||
        __builtin_memcmp(iov_base, "PATCH", 5) == 0 ||
        __builtin_memcmp(iov_base, "HTTP", 4) == 0)
    {
    //     bpf_printk("iov.iov_base:  %s\n", iov_base);
    // }

    // if (__builtin_memcmp(iov_base, "GET", 3) == 0)
    // {

        __u32 src_ip4 = BPF_CORE_READ(l_sock, __sk_common.skc_rcv_saddr);
        __u16 src_port = bpf_ntohs(READ_KERN(l_sock->__sk_common.skc_num));
        __u32 dst_ip4 = BPF_CORE_READ(l_sock, __sk_common.skc_daddr);
        __u16 dst_port = bpf_ntohs(READ_KERN(l_sock->__sk_common.skc_dport));
        bpf_printk("src_ip4:%u, src_port:%d\n", src_ip4, src_port);
        bpf_printk("dst_ip4:%u, dst_port:%d\n", dst_ip4, dst_port);

        bpf_printk("iov_base is true\n");
        bpf_printk("really iov_len is %d\n", iov_len);
        bpf_printk("iov.iov_base:  %s\n", iov_base);

        info = bpf_ringbuf_reserve(&map_of_http_probe, sizeof(struct http_probe_info), 0);
        if (info == NULL) {
            bpf_printk("info is NULL");
            return 0;
        }
        if (iov_len > CONN_DATA_MAX_SIZE)
            iov_len = CONN_DATA_MAX_SIZE;
        bpf_probe_read_user(info->data, iov_len, &iov_ptr->iov_base);
        info->iov_len = iov_len;
        bpf_ringbuf_submit(info, 0);
    }
    return 1;
}

KPROBE(tcp_recvmsg, pt_regs)
{
    struct sock *l_sock = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *const msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    struct iovec *iov_ptr = NULL;
    __u64 iov_len = 0;
    __u64 tmp_iov_len = 0;
    char iov_base[256] = {};
    int ret = 0;
    struct http_probe_info *info = NULL;

    if (l_sock == NULL) {
        bpf_printk("l_sock is NULL\n");
        return 0;
    }

    //bpf_printk("tcp_recvmsg\n");
    if (bpf_core_field_exists(msg->msg_iov))
        iov_ptr = (struct iovec *)READ_KERN(msg->msg_iov);


    if (iov_ptr == NULL) {
        bpf_printk("iov_ptr is NULL\n");
        return 0;
    }

    tmp_iov_len = 256;
    ret = bpf_probe_read(iov_base, tmp_iov_len, &iov_ptr->iov_base);
    if (ret != 0) {
        bpf_printk("recvmsg 5 ret:%d\n", ret);
        return 0;
    }
    ret = bpf_probe_read(&iov_len, sizeof(__u64), &iov_ptr->iov_len);
    if (ret != 0) {
        bpf_printk("recvmsg 3 ret:%d\n", ret);
        return 0;
    }

    //bpf_printk("recvmsg iov.iov_base:  %s\n", iov_base);
    if (__builtin_memcmp(iov_base, "GET", 3) == 0 || 
        __builtin_memcmp(iov_base, "POST", 4) == 0 ||
        __builtin_memcmp(iov_base, "PUT", 3) == 0 ||
        __builtin_memcmp(iov_base, "DELETE", 6) == 0 ||
        __builtin_memcmp(iov_base, "HEAD", 4) == 0 ||
        __builtin_memcmp(iov_base, "OPTIONS", 7) == 0 ||
        __builtin_memcmp(iov_base, "PATCH", 5) == 0 ||
        __builtin_memcmp(iov_base, "HTTP", 4) == 0)
    {
        __u32 src_ip4 = READ_KERN(l_sock->__sk_common.skc_rcv_saddr);
        __u16 src_port = bpf_ntohs(READ_KERN(l_sock->__sk_common.skc_num));
        __u32 dst_ip4 = READ_KERN(l_sock->__sk_common.skc_daddr);
        __u16 dst_port = bpf_ntohs(READ_KERN(l_sock->__sk_common.skc_dport));
        bpf_printk("src_ip4:%u, src_port:%d\n", src_ip4, src_port);
        bpf_printk("dst_ip4:%u, dst_port:%d\n", dst_ip4, dst_port);
        bpf_printk("recvmsg iov.iov_len: %d\n", iov_len);
        bpf_printk("recvmsg iov.iov_base:  %s\n", iov_base);
    }
    return 1;
}
char _license[] SEC("license") = "GPL";