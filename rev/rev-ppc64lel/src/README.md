PPC64LEL
========

This is a Linux reverse engineering challenge consisting of a little-endian
PowerPC 64-bit ELF binary that performs checks on a key given as input while
constantly changing runtime endianness via the special PPC64 `switch_endian`
Linux syscall. The checks verify between 1 and 6 bits of the key at a time in a
recursive manner where the function call tree is randomly generated at build
time.

The challenge binary also depends on libsodium (Debian `libsodium23` package
i.e. `libsodium.so.23`).


Building
--------

You will need a cross-compilation toolchain for PPC64LE. You can specify the
target with `make TARGET=XXX`. By default `TARGET=powerpc64le-linux-gnu` is
used. Building will also download and cross-compile
[libsodium](https://github.com/jedisct1/libsodium) 1.0.18 for PPC64LE using its
configure script plus `make`. You will therefore also need libsodium build
dependencies.

Use `make -j` to build the challenge binary at `build/PPC64LEL`.

Use `make -j archive` to build the `PPC64LEL.tar.gz` archive to distribute to
players.

The files [`build/verifier.c`](build/verifier.c) and
[`build/verifier.h`](build/verifier.c) are randomly generated at build time
based on a fixed seed contained in the `Makefile`. They are included in this
repository just for clarity.


Running
-------

This is a static reverse-engineering challenge, so no running backend is needed.
The challenge binary itself can be run on a Linux PPC64LE system that provides
the `switch_endian` syscall. See [`PLAYER_README.md`](./PLAYER_README.md) for an
example using a Debian 12 PPC64LE image with QEMU.


Solution
--------

See complete solution scripts in [`../solver`](../solver).
