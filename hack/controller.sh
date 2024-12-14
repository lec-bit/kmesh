#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)
. $ROOT_DIR/hack/utils.sh
GOPATH=$(go env GOPATH)
KERNEL_OUTPUT=$(uname -r)

if [[ $KERNEL_OUTPUT == *"oe2303"* ]]; then
    KERNEL_VERSION="oe2303"
    find . -type f -not -name "controller.sh" -exec sed -i 's|"kmesh.net/kmesh/bpf/kmesh/bpf2go"|"kmesh.net/kmesh/bpf/kmesh/bpf2go/oe2303/bpf2go"|g' {} +
elif [[ $KERNEL_OUTPUT == *"hce"* ]]; then
    KERNEL_VERSION="hce"
    find . -type f -not -name "controller.sh" -exec sed -i 's|"kmesh.net/kmesh/bpf/kmesh/bpf2go"|"kmesh.net/kmesh/bpf/kmesh/bpf2go/hce/bpf2go"|g' {} +
elif [[ $KERNEL_OUTPUT == *"ubuntu"* ]]; then
    KERNEL_VERSION="ubuntu"
    find . -type f -not -name "controller.sh" -exec sed -i 's|"kmesh.net/kmesh/bpf/kmesh/bpf2go"|"kmesh.net/kmesh/bpf/kmesh/bpf2go/ubuntu/bpf2go"|g' {} +
else
    KERNEL_VERSION=""
fi

go mod tidy
cp /lib/modules/kmesh/kmesh.ko $ROOT_DIR/kernel/ko_src/kmesh/
cp /usr/share/kmesh/bpf2go/* $ROOT_DIR/bpf/kmesh/bpf2go/$KERNEL_VERSION
# cp /usr/share/kmesh/normal/bpf2go/*.o $GOPATH/pkg/mod/github.com/lec-bit/my-code@v1.0.3/normal/bpf2go
# cp /usr/share/kmesh/enhanced/bpf2go/*.o $GOPATH/pkg/mod/github.com/lec-bit/my-code@v1.0.3/enhanced/bpf2go
cp /usr/lib64/libkmesh_api_v2_c.so $ROOT_DIR/api/v2-c/
cp /usr/lib64/libkmesh_deserial.so $ROOT_DIR/bpf/deserialization_to_bpf_map/
echo $ROOT_DIR

function build_kmesh_controller() {
    local container_id=$1
    docker exec $container_id git config --global --add safe.directory /kmesh
    docker exec $container_id sh /kmesh/build.sh -k
    docker exec $container_id sh /kmesh/build.sh -i
    docker exec $container_id sh -c "$(declare -f copy_to_host); copy_to_host"
}

container_id=$(run_docker_container)
build_kmesh_controller $container_id
clean_container $container_id