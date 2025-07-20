#!/bin/sh
TIMEOUT=100

qemu-system-x86_64 \
    -kernel ./bzImage \
    -initrd ./initramfs.cpio.gz \
    -cpu qemu64,+smap,+smep \
    -smp 1 \
    -m 1G \
    -append "console=ttyS0 quiet loglevel=3 oops=panic panic_on_warn=1 panic=-1 pti=on cfi=norand unprivileged_bpf_disabled=1" \
    -monitor /dev/null \
    -nographic \
    -no-reboot \
    -drive file=flag.txt,format=raw,media=disk,if=virtio,readonly=on