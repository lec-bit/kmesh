#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)

. $ROOT_DIR/hack/utils.sh

uname -a
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
ls /boot
ls /sys/kernel/btf
ls /sys/kernel/btf/vmlinux
bpftool feature probe kernel | grep -E BTF

echo "Building kmesh kernel module"

bash kmesh_macros_env_kernel.sh
make kmesh-ko
container_id=$(run_docker_container)
build_kmesh $container_id
clean_container $container_id

sudo chmod -R a+r out/
