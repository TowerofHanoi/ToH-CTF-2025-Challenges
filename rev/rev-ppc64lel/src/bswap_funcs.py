#!/usr/bin/env python3
#
# @mebeim - 2025-03-30
#
# Swap byte order of instructions where needed:
# - Instructions in any function whose name starts with "be_func_", excluding
#   chunks between .start_asm_wrapped_callXXX and .end_asm_wrapped_callXXX
#   labels.
# - Instructions betwen any .start_be_insnsXXX and .end_be_insnsXXX labels
#

import re
import sys
from collections import namedtuple
from os import getenv
from pathlib import Path
from struct import unpack
from subprocess import check_call, check_output

Section = namedtuple('Section', ('name', 'vaddr', 'off', 'size'))
Symbol = namedtuple('Symbol', ('vaddr', 'size', 'type', 'name'))


# Convenience class, mostly copy-pasted from existing code of mine
class ELF:
	__slots__ = (
		'path', 'file', 'bits32', 'big_endian', 'e_machine', 'e_flags',
		'__sections', '__symbols', '__functions'
	)

	def __init__(self, path: Path):
		self.path = Path(path)
		self.file        = self.path.open('rb')
		self.__sections  = None
		self.__symbols   = None
		self.__functions = None

		magic, ei_class, ei_data = unpack('<4sBB', self.file.read(6))
		assert magic == b'\x7fELF'

		if ei_class == 1:
			self.bits32 = True
		elif ei_class == 2:
			self.bits32 = False
		else:
			sys.exit(f'Invalid ELF e_ident[EI_CLASS] = {ei_class}')

		if ei_data == 1:
			self.big_endian = False
		elif ei_data == 2:
			self.big_endian = True
		else:
			sys.exit(f'Invalid ELF e_ident[EI_DATA] = {ei_data}')

		unpack_endian = '<>'[self.big_endian]
		assert self.file.seek(0x12) == 0x12
		self.e_machine = unpack(unpack_endian + 'H', self.file.read(2))[0]

		assert self.file.seek(0x24) == 0x24
		self.e_flags = unpack(unpack_endian + 'L', self.file.read(4))[0]

	@property
	def sections(self) -> dict[str,Section]:
		if self.__sections is not None:
			return self.__sections

		# We actually only really care about SHT_PROGBITS or SHT_NOBITS
		exp = re.compile(r'\s([.\w]+)\s+(PROGBITS|NOBITS)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)')
		out = check_output(['readelf', '-WS', self.path], text=True)
		secs = {}

		for match in exp.finditer(out):
			name, _, va, off, sz = match.groups()
			secs[name] = Section(name, int(va, 16), int(off, 16), int(sz, 16))

		self.__sections = secs
		return secs

	@property
	def symbols(self) -> dict[str,Symbol]:
		if self.__symbols is None:
			self.__extract_symbols()
		return self.__symbols

	@property
	def functions(self) -> dict[str,Symbol]:
		if self.__functions is None:
			self.__extract_symbols()
		return self.__functions

	def __extract_symbols(self):
		exp = re.compile(r'\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\w+).+\s+(\S+)$')
		out = check_output(['readelf', '-Ws', self.path], text=True).splitlines()
		syms = {}
		funcs = {}

		for line in out:
			match = exp.search(line)
			if not match:
				continue

			vaddr, sz, typ, name = match.groups()
			vaddr = int(vaddr, 16)

			sym = Symbol(vaddr, int(sz), typ, name)
			syms[sym.name] = sym

			if typ == 'FUNC':
				funcs[sym.name] = sym

		self.__symbols = syms
		self.__functions = funcs

	def vaddr_to_file_offset(self, vaddr: int) -> int:
		for sec in self.sections.values():
			if sec.vaddr <= vaddr < sec.vaddr + sec.size:
				return sec.off + vaddr - sec.vaddr
		raise ValueError('vaddr not in range of any known section')

	def vaddr_read(self, vaddr: int, size: int) -> bytes:
		off = self.vaddr_to_file_offset(vaddr)
		assert self.file.seek(off) == off
		return self.file.read(size)


def find_chunks(elf: ELF, start_label_prefix: str, end_label_prefix: str) \
		-> tuple[list[Symbol],list[range]]:
	labels = []
	chunks = []
	start = None

	for s in elf.symbols.values():
		if s.name.startswith(start_label_prefix) or s.name.startswith(end_label_prefix):
			labels.append(s)

	assert len(labels) % 2 == 0
	labels.sort(key=lambda lbl: lbl.vaddr)

	for i, lbl in enumerate(labels):
		if i % 2 == 0:
			assert lbl.name.startswith(start_label_prefix)
			start = lbl.vaddr
		else:
			assert lbl.name.startswith(end_label_prefix)
			chunks.append(range(start, lbl.vaddr))

	return labels, chunks


def main() -> int|str:
	if len(sys.argv) != 2:
		return f'Usage: {sys.argv[0]} ELF'

	elf_path = Path(sys.argv[1])
	elf = ELF(elf_path)
	assert not elf.bits32
	assert not elf.big_endian
	assert elf.e_machine == 21 # EM_PPC64

	_, wrapped_calls = find_chunks(elf, '.start_asm_wrapped_call', '.end_asm_wrapped_call')
	text = elf.sections['.text']
	writes = {}

	for func in elf.functions.values():
		if not func.name.startswith('be_func_'):
			continue

		assert func.size > 0 and func.size % 4 == 0
		assert text.vaddr <= func.vaddr
		assert func.vaddr + func.size <= text.vaddr + text.size

		print('Byte-swapping function', func.name, f'({func.vaddr:#x}-{func.vaddr + func.size:#x})')
		code = elf.vaddr_read(func.vaddr, func.size)
		new_code = b''

		for i in range(0, len(code), 4):
			vaddr = func.vaddr + i

			# Don't byte-swap inlined LE/BE endian_switch asm chunks
			if any(vaddr in x for x in wrapped_calls):
				new_code += code[i:i + 4]
			else:
				new_code += code[i:i + 4][::-1]

		file_off = elf.vaddr_to_file_offset(func.vaddr)
		assert file_off not in writes
		writes[file_off] = new_code

	be_labels, be_chunks = find_chunks(elf, '.start_be_insns', '.end_be_insns')

	for vrange in be_chunks:
		print('Byte-swapping chunk', f'{vrange.start:#x}-{vrange.stop:#x}')

		file_off = elf.vaddr_to_file_offset(vrange.start)
		assert file_off not in writes

		code = elf.vaddr_read(vrange.start, vrange.stop - vrange.start)
		new_code = b''.join(code[i:i + 4][::-1] for i in range(0, len(code), 4))
		writes[file_off] = new_code

	with elf_path.open('rb+') as f:
		for file_off, data in writes.items():
			assert f.seek(file_off, 0) == file_off
			f.write(data)

	# Strip .be_insns[...] labels for less eye sore while debugging
	cmd = [getenv('STRIP', 'powerpc64le-linux-gnu-strip')]
	for lbl in be_labels:
		cmd.append('--strip-symbol=' + lbl.name)

	cmd.append(elf_path)
	check_call(cmd)

	return 0


if __name__ == '__main__':
	sys.exit(main())
