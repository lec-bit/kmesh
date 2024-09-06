# Usage:
# docker run -itd --privileged=true -v /etc/cni/net.d:/etc/cni/net.d -v /opt/cni/bin:/opt/cni/bin -v /mnt:/mnt -v /sys/fs/bpf:/sys/fs/bpf -v /lib/modules:/lib/modules --name kmesh kmesh:latest
#
FROM openeuler/openeuler:23.09

WORKDIR /kmesh

RUN \
    yum install -y kmod util-linux iptables libbpf-devel protobuf-c-devel libboundscheck&& \
    mkdir -p /usr/share/kmesh

COPY kmesh-bpf-docker/libkmesh_api_v2_c.so /usr/lib64/
COPY kmesh-bpf-docker/libkmesh_deserial.so /usr/lib64/
COPY kmesh-bpf-docker/kmesh-bpf /usr/bin/
COPY kmesh-bpf-docker/start_kmesh_bpf.sh /kmesh
COPY kmesh-bpf-docker/kmesh.ko /kmesh
