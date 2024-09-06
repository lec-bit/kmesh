#/bin/bash

mkdir -p kmesh-bpf-docker
cp /usr/lib64/libkmesh_api_v2_c.so kmesh-bpf-docker
cp /usr/lib64/libkmesh_deserial.so kmesh-bpf-docker
cp /usr/bin/kmesh-bpf kmesh-bpf-docker
cp /usr/share/kmesh/start_kmesh_bpf.sh kmesh-bpf-docker
cp /lib/modules/kmesh/kmesh.ko kmesh-bpf-docker
