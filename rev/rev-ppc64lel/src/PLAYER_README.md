Having trouble running the binary? Try this:

```sh
wget 'https://cloudfront.debian.net/cdimage/cloud/bookworm/20250316-2053/debian-12-nocloud-ppc64el-20250316-2053.qcow2'

qemu-system-ppc64 \
	-machine pseries,x-vof=off \
	-nographic \
	-drive file=debian-12-nocloud-ppc64el-20250316-2053.qcow2,index=0,media=disk,format=qcow2 \
	-drive file=./PPC64LEL,index=1,media=disk,format=raw

# Inside VM
cat /dev/sdb > PPC64LEL
chmod +x PPC64LEL
./PPC64LEL
```
