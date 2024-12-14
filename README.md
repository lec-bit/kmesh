该代码仓用于提供Kmesh for HuaweiCloud项目部分所需文件，代码fork于

[Kmesh]: https://github.com/kmesh-net/kmesh

仓最新release，由于kmesh数据面部分编译产物和操作系统版本强耦合，在此基础上提供如下能力：

1. 归档Kmesh在不同操作系统下编译出的ebpf程序、ko文件、so文件并打包成kmesh-devel.rpm包；
2. 归档Kmesh在不同操作系统下编译出的ebpf程序对应bpf2go文件于代码仓中；
3. 添加编译相关脚本文件，
   1. 提供make controller命令：从kmesh-devel包安装目录中取文件并编译kmesh控制面二进制
   2. 提供make kmesh-devel命令：制作出kmesh-devel.rpm包



用户使用指南：

例：在openeuler 2303环境中编译kmesh

1. 根据自己操作系统环境选择并安装kmesh-devel.rpm
2. 根据自己操作系统环境修改import路径，"github.com/kmesh.net/kmesh/bpf/kmesh/bpf2go/oe2303"
3. 执行make controller
4. 制作镜像[可选]，执行`docker build -f build/docker/dockerfile -t ghcr.io/kmesh-net/kmesh:latest .`