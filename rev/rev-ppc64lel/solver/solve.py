#!/usr/bin/env python3
#
# @mebeim - 2025-04-06
#
# Setup: you should have the challenge running under qemu-system-ppc64le with
# GDB debugging enabled on port 1234. The challenge binary should run in a loop
# in QEMU like this:
#
#     while :; do
#         ./PPC64LEL aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
#         sleep .05
#     done
#
# This script will repeatedly attach to QEMU via GDB and run a GDB script to
# solve one check (from 1 to 8 bits of the key) at a time.
#

import sys
from ast import literal_eval
from hashlib import blake2b
from pathlib import Path
from subprocess import Popen, PIPE
from tempfile import NamedTemporaryFile
from textwrap import dedent

from Crypto.Cipher import ChaCha20


# These two addrs will change when the program is recompiled. They are
# hardcoded to work with the original binary. Change them after compiling.
#
# Start: right before bctrl to call the "root" verifier function. The input key
# addr (after hex decoding) should be in r3 at this point of execution.
START = 0x1000f380
# Goal: right after the return from the "root" verifier function, in the
# good branch that returns a pointer to main (not NULL).
GOAL = 0x1000f430


class Solver:
	def __init__(self):
		self.endian     = 'little'
		self.start_addr = START
		self.bp_addr    = START
		self.goal_addr  = GOAL
		self.key        = bytearray(b'\x00' * 48)

		self.gdb_script = Path('solve_gdb_script.py')
		if not self.gdb_script.exists():
			sys.exit('GDB script "solve_gdb_script.py" not found in current directory!')

	def update_key(self, bits: list[int], val: int):
		for i, bit in enumerate(bits):
			bitval = (val >> i) & 1
			self.key[bit // 8] |= bitval << (bit % 8)

	def prepare_script(self, out_path: str):
		return(dedent(f'''
			target remote localhost:1234

			set python print-stack full

			b *{self.start_addr}
			command
				set $key_addr = $r3
				pi goal_addr = {self.goal_addr!r}
				pi key_so_far = {self.key.hex()!r}
				pi out_path = {out_path!r}
				source {self.gdb_script.as_posix()}

				del 1
				set endian {self.endian}
				continue
			end

			b *{self.bp_addr}
			command
				solve
			end

			continue
		'''))

	def run_gdb(self):
		with NamedTemporaryFile('w') as f, NamedTemporaryFile('r') as pyf:
			f.write(self.prepare_script(pyf.name))
			f.flush()

			p = Popen(['gdb-multiarch', '-batch', '-x', f.name], stdout=PIPE, stderr=PIPE, text=True)
			out, err = p.communicate()
			pyout = pyf.read().strip()

		if 'DEBUG' in sys.argv[1:]:
			print(err)
			print('---')
			print(out)
			print('---')
			print(pyout)
			print('===============')

		if pyout == 'trap':
			return False, None

		if pyout == 'goal':
			return True, None

		endian, last_addr, bits, value = pyout.splitlines()
		last_addr = int(last_addr, 0)
		bits = literal_eval(bits)

		if value == '?':
			assert len(bits) == 1
			value = None
		else:
			value = int(value, 0)

		return False, (endian, last_addr, bits, value)

	def find_key(self):
		self.info = []
		self.endian = 'little'

		while 1:
			print('Key:', self.key.hex())

			done, res = self.run_gdb()
			if done:
				break

			endian, last_addr, bits, value = res

			if value is None:
				# 1 bit value, test 0
				value = 0
				self.endian = endian
				self.bp_addr = last_addr
				done, res = self.run_gdb()
				if done:
					break

				if res is None or res[1] == last_addr:
					# Not 0, test 1
					self.update_key(bits, 1)

					done, res = self.run_gdb()
					if done:
						break

					endian, last_addr, bits, value = res

			self.endian = endian
			self.bp_addr = last_addr
			self.update_key(bits, value)

		print('Key:', self.key.hex())
		print('Key is complete!')
		return self.key


def main():
	s = Solver()
	key = s.find_key()
	assert len(key) == 48

	chacha_key = blake2b(key, digest_size=32).digest()
	nonce = b'\0' * 8
	ctx = bytearray([
		0x4f, 0x4c, 0xb0, 0xd0, 0x15, 0x96, 0xf9, 0xe1, 0x43, 0xcb, 0x72, 0xa0,
		0x1f, 0x67, 0x84, 0x2e, 0xe2, 0x34, 0xf4, 0xfe, 0x61, 0xb3, 0xf1, 0xea,
		0xf2, 0xfc, 0xe5, 0x90, 0x61, 0xb3, 0xac, 0x81, 0x99, 0x42, 0xad, 0x9b,
		0x14, 0x09, 0xf5, 0xab, 0xe9, 0x74, 0x6b, 0x4d, 0x26, 0x81, 0x29, 0x0f,
		0xe0, 0x1b, 0x13, 0x54
	])

	cipher = ChaCha20.new(key=chacha_key, nonce=nonce)
	flag = cipher.decrypt(ctx)
	print('Flag:', flag.decode())



if __name__ == '__main__':
	main()
