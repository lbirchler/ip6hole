#/bin/bash -x

bpftool btf dump file ${1:-/sys/kernel/btf/vmlinux} format c