#
# @mebeim - 2025-04-06
#
# Add "solve" GDB command to identify and test values for some bits of the key.
# Automatically single-step and step over switch_endian syscalls, correctly
# handling the endianness change (assuming the syscall is successful). Return
# information to the caller about the bits being tested by the next verifier
# function call and about the current endianness.
#
# NOTE: this script needs some vars set from GDB command line to work:
#
#    key_so_far: hex string of current key guess
#    goal_addr : address to match as the goal (if we get here, key_so_far is correct)
#    out_path  : output file where info is written for the caller
#

from collections import deque

import gdb


def getreg(name, cast_to=gdb.lookup_type('unsigned long')):
	return int(gdb.selected_frame().read_register(name).cast(cast_to))


def read_bytes(addr, size):
	return bytes(gdb.selected_inferior().read_memory(addr, size))


def write_bytes(addr, data: bytes):
	return gdb.selected_inferior().write_memory(addr, data)


def read_u8(addr):
	try:
		return int.from_bytes(read_bytes(addr, 1), 'little')
	except gdb.MemoryError:
		return None


def write_u8(addr, val: int):
	write_bytes(addr, val.to_bytes(1, 'little'))


def get_endianness():
	endian = gdb.execute('show endian', to_string=True).strip()
	assert 'little' in endian or 'big' in endian
	return 'little' if 'little' in endian else 'big'


def set_endianness(endian):
	gdb.execute('set endian ' + endian)


def parse_insn(insn: str):
	pc, insn = insn.strip().split(maxsplit=1)
	insn = insn.split(maxsplit=1)
	opcode = insn[0]
	opargs = [] if len(insn) == 1 else insn[1].split(',')
	return opcode, opargs


def disasm_one_insn(addr):
	insn = gdb.execute('x/i ' + str(addr), to_string=True)
	if insn.startswith('=>'):
		insn = insn[2:]

	return parse_insn(insn)


def disasm(addr: int, n_insns: int):
	asm = gdb.execute(f'x/{n_insns}i ' + str(addr), to_string=True).splitlines()
	return list(map(parse_insn, asm))


def switch_endian(pc: int):
	endian = get_endianness()
	insn = int.from_bytes(gdb.selected_inferior().read_memory(pc, 4), endian)

	# Ensure that current insn is "sc" and that r0 is 363 (__NR_switch_endian)
	if insn != 0x44000002 or gdb.parse_and_eval('$r0') != 363:
		print('Not a switch_endian syscall!')
		return

	bp = gdb.Breakpoint('*($pc + 4)')
	set_endianness('big' if endian == 'little' else 'little')
	gdb.execute('continue')
	bp.delete()


class SolveCmd(gdb.Command):
	def __init__ (self):
		super(SolveCmd, self).__init__ ('solve',
			gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE, True)

	def round_done(self, resume_addr, bits, value):
		self.fout.write(f'{get_endianness()}\n{resume_addr:#x}\n{bits}\n{value}\n')
		self.fout.flush()
		self.fout.close()
		gdb.execute('quit')

	def round_done_trap(self):
		self.fout.write('trap\n')
		self.fout.close()
		gdb.execute('quit')

	def round_done_found_goal(self):
		self.fout.write('goal\n')
		self.fout.close()
		gdb.execute('quit')

	def get_call_args(self, pc: int):
		# Check instructions backwards to see the arguments that were passed.
		# Assume the following situation:
		#
		#     <not a mr insn>
		#     ...
		#     mr    r6,xx
		#     mr    r5,xx
		#     mr    r4,xx
		#     mr    r3,xx
		#     mtctr r30
		#  => bctrl

		pc -= 8
		args = []

		while 1:
			opcode, opargs = disasm_one_insn(pc)
			if opcode != 'mr':
				break

			args.append(getreg(opargs[0]))
			pc -= 4

		return args

	def solve_leaf(self, pc: int, nbits: int):
		xor_vals = []
		found_not = False
		insns = deque(disasm(pc, 100))

		while insns:
			opcode, opargs = insns.popleft()
			if opcode in ('beq', 'bne', '.long'):
				print(f'Func {pc:#x} is NOT a leaf')
				return None

			if opcode == 'blr':
				break

			# Follow unconditional branches
			if opcode == 'b':
				insns = deque(disasm(int(opargs[0], 0), 100))
				continue

			if opcode == 'not':
				found_not = True
			elif opcode == 'xori':
				xor_vals.append(int(opargs[-1], 0))
		else:
			assert False, f'Could not determine if func {pc:#x} is a leaf'

		print(f'Func {pc:#x} is a leaf')
		assert nbits == 1 or len(xor_vals) in (1, 2)

		if nbits > 1:
			if len(xor_vals) == 2:
				assert xor_vals[1] == 1
				return xor_vals[0]

			assert xor_vals[0] == 1
			return 0

		return int(found_not)

	def invoke(self, args, from_tty):
		# out_path and goal are provided by caller gdb script
		global out_path, goal_addr
		self.fout = open(out_path, 'w')

		bits = []
		last_value = None

		while 1:
			pc = getreg('pc')
			if pc == goal_addr:
				self.round_done_found_goal()

			# Check if we switched to kernel code
			if pc & 0xffffffff00000000 == 0xc000000000000000 or pc & 0x00000000ffffffff == 0x00000000000000c0:
				# These prints are just for debugging purposes, addresses depend
				# on exact kernel
				if pc == 0xc000000000004700 or pc == 0x00470000000000c0:
					print('Kernel trap: illegal instruction')
				elif pc == 0xc000000000004380 or pc == 0x80430000000000c0:
					print('Kernel trap: segfault')
				else:
					print('Kernel trap: other')

				self.round_done_trap()

			opcode, opargs = disasm_one_insn(pc)
			# print(hex(pc), opcode, ','.join(opargs))

			if opcode == 'sc':
				switch_endian(pc)
				continue

			if opcode == 'cmpwi':
				# Multi-bit compare
				last_value = int(opargs[1])
			elif opcode == 'andi.' and opargs[0] == opargs[1] and opargs[2] == '1':
				# Single-bit compare, make caller test it
				self.round_done(pc + 4, bits, '?')
			elif opcode == 'bctrl':
				# Call to next function (first arg is key pointer)
				_, *bits = self.get_call_args(pc)

				# Special case for leaf calls
				ctr = getreg('ctr')
				value = self.solve_leaf(ctr, len(bits))
				if value is not None:
					assert len(bits) != 0
					self.round_done(ctr, bits, value)
			elif opcode in ('beq', 'bne'):
				# First comparison of each function checks key bits
				if last_value is not None:
					self.round_done(pc, bits, last_value)

			gdb.execute('si')


SolveCmd()

# key_so_far is provided by caller gdb script
key_so_far = bytes.fromhex(key_so_far)
write_bytes(getreg('r3'), key_so_far)
