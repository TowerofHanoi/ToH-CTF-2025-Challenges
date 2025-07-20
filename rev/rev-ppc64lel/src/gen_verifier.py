#!/usr/bin/env python3
#
# @mebeim - 2025-04-06
#

import sys
from collections import deque
from os import urandom
from pathlib import Path
from random import Random
from textwrap import dedent, indent


class Func:
	def __init__(self, data: bytes, big_endian: bool, bits_to_check: list[int], \
			negate_check: bool=False):
		self.data = data
		self.big_endian = big_endian
		self.bits_to_check = bits_to_check
		self.n_bits_to_check = len(bits_to_check)
		self.negate_check = negate_check
		assert 1 <= self.n_bits_to_check <= 6

		self.n_args = 1 + self.n_bits_to_check
		self.arg_types = ['uint8_t *'] + ['unsigned'] * self.n_bits_to_check
		self.arg_names = ['k'] + list('abcdef'[:self.n_bits_to_check])
		self.var_names = [f'bit{i}' for i in self.bits_to_check]

		self.name = f'verify{len(self.bits_to_check)}_' + '_'.join(map(str, self.bits_to_check))
		self.calls = []

		if self.big_endian:
			self.name = 'be_func_' + self.name

	def __repr__(self):
		return f'<Func {self.name} #calls={len(self.calls)} {id(self):#x}>'

	def _gen_check(self) -> str:
		assert len(self.bits_to_check) == len(self.var_names)

		expected = 0
		expr_bits = []

		for i, bit in enumerate(self.bits_to_check):
			val = (self.data[bit // 8] >> (bit % 8)) & 1
			expected |= (val << i)
			expr_bits.append(f'({self.var_names[i]} << {i})')

		expr = ' | '.join(expr_bits)
		eq = '!=' if self.negate_check else '=='
		return f'({expr}) {eq} {expected:#x}'

	def _gen_call(self, callee: 'Func', bad=False) -> str:
		call_big_endian = callee.big_endian ^ bad
		args = ', '.join(map(str, callee.bits_to_check))
		endian = 'BE' if call_big_endian else 'LE'
		return f'MAGIC_CALL_{endian}{callee.n_args}({callee.name}, {self.arg_names[0]}, {args})'

	def _extract_bit(self, x: str):
		return f'({self.arg_names[0]}[{x} / 8] >> ({x} % 8)) & 1'

	@property
	def signature(self) -> str:
		args = ', '.join(f'{t} {n}' for t, n in zip(self.arg_types, self.arg_names))
		return f'unsigned {self.name}({args})'

	@property
	def definition(self) -> str:
		if self.calls:
			# Forward work to callees, verification is implicit in how the call
			# is made (matching callee endianness or not)
			good = []
			bad = []
			for callee in self.calls:
				good.append(f'res += {self._gen_call(callee)};')
				bad.append(f'res += {self._gen_call(callee, bad=True)};')

			bad.append('res += 1;')
			good_code = '\n\t\t\t\t'.join(good)
			bad_code = '\n\t\t\t\t'.join(bad)
		else:
			# No further functions to call, just return check result
			good_code = 'res = 0;'
			bad_code = 'res = 1;'

		if self.negate_check:
			good_code, bad_code = bad_code, good_code

		extr = []
		for v, a in zip(self.var_names, self.arg_names[1:]):
			extr.append(f'bool {v} = {self._extract_bit(a)};')

		extr_code = '\n\t\t\t'.join(extr)

		res = self.signature + ' {\n'
		res += indent(dedent(f'''\
			{extr_code}
			unsigned res = 0;

			if ({self._gen_check()}) {{
				{good_code}
			}} else {{
				{bad_code}
			}}

			return res;
		'''), '\t')
		return res + '}'


class Verifier:
	# Max calls per function
	MAX_CHILDREN = 8
	# Number of most recently generated functions to pick as new callers
	PARENT_CHOICE_WINDOW = 128

	def __init__(self, out_source_path: Path, out_header_path: Path, \
			data: bytes, rng_seed: str|None=None):
		self.out_source_path = out_source_path
		self.out_header_path = out_header_path
		self.data = data
		self.rng = Random(rng_seed)
		self.root_function = None
		self.functions = None

		assert '"' not in str(out_header_path)
		assert len(self.data) >= 2, 'too small cmon'

	def _choose_parent(self, funcs: list[Func]):
		# Pick a random node among those that don't have too many calls
		avail = list(filter(lambda n: len(n.calls) < self.MAX_CHILDREN, funcs))
		assert avail
		return self.rng.choice(avail)

	def _gen_call_tree(self, schedule: deque[list[int]]) -> tuple[Func,list[Func]]:
		root = Func(self.data, False, schedule.popleft(), bool(self.rng.getrandbits(1)))
		funcs = [root]

		while schedule:
			parent = self._choose_parent(funcs[-self.PARENT_CHOICE_WINDOW:])
			node = Func(self.data, bool(self.rng.getrandbits(1)),
				schedule.popleft(), bool(self.rng.getrandbits(1)))
			parent.calls.append(node)
			funcs.append(node)

		return root, funcs

	def _dump_tree(self, root: Func, depth: int=0):
		print('  ' * depth, 'depth', depth, repr(root))
		for child in root.calls:
			self._dump_tree(child, depth + 1)

	def _gen_functions(self):
		all_bits = list(range(len(self.data) * 8))
		self.rng.shuffle(all_bits)

		# Schedule bits to be verified by each function
		q = deque(all_bits)
		schedule = deque([])

		while q:
			# Choose 1 to 6 bits to verify with this function
			n_bits = self.rng.randint(1, min(6, len(q)))
			bits = [q.popleft() for _ in range(n_bits)]
			schedule.append(bits)

		# Generate call tree and assign bits to each function
		self.root_function, self.functions = self._gen_call_tree(schedule)
		# self._dump_tree(self.root_function)

	def _entry_function_signature(self) -> str:
		return 'uint8_t *verify(const char *key_hex)'

	def _boilerplate(self) -> str:
		assert not self.root_function.big_endian

		bits = ', '.join(map(str, self.root_function.bits_to_check))
		n_bits = len(self.root_function.bits_to_check)

		return dedent(f'''\
			static int hex_check(const char *in) {{
				while (*in) {{
					if ((*in < '0' || *in > '9') && (*in < 'a' || *in > 'f'))
						return -1;
					in++;
				}}
				return 0;
			}}

			static void hex_decode(uint8_t *out, const char *in) {{
				while (*in) {{
					uint8_t hi = (*in >= 'a') ? (*in - 'a' + 10) : (*in - '0');
					uint8_t lo = (in[1] >= 'a') ? (in[1] - 'a' + 10) : (in[1] - '0');
					*out++ = (hi << 4) | lo;
					in += 2;
				}}
			}}

			uint8_t *verify(const char *key_hex) {{
				uint8_t *key;

				if (strlen(key_hex) != {len(self.data) * 2})
					errx(1, "Malformed key");

				if (hex_check(key_hex) != 0)
					errx(1, "Malformed key");

				key = calloc({len(self.data)}, 1);
				hex_decode(key, key_hex);

				if (MAGIC_CALL_LE{n_bits + 1}({self.root_function.name}, key, {bits}) != 0) {{
					free(key);
					return NULL;
				}}

				return key;
			}}
		''')

	def gen_c_header(self) -> str:
		if self.functions is None:
			self._gen_functions()

		res = '#pragma once\n\n'
		res += '#include <stdbool.h>\n'
		res += '#include <stdint.h>\n\n'
		res += f'#define VERIFIER_KEY_SIZE {len(self.data)}\n\n'
		res += self._entry_function_signature() + ';\n'
		res += '\n'.join((f.signature + ';') for f in self.functions)
		return res + '\n'

	def gen_c_source(self) -> str:
		if self.functions is None:
			self._gen_functions()

		h_path = self.out_header_path.relative_to(self.out_source_path.parent)
		res = '#include <err.h>\n'
		res += '#include <stdbool.h>\n'
		res += '#include <stdint.h>\n'
		res += '#include <stdlib.h>\n'
		res += '#include <string.h>\n\n'
		res += '#include "magic.h"\n'
		res += f'#include "{str(h_path)}"\n\n'
		res += self._boilerplate() + '\n'
		res += '\n\n'.join(f.definition for f in self.functions)
		return res + '\n'


def main() -> int|str:
	if len(sys.argv) not in (4, 5):
		return f'Usage: {sys.argv[0]} path/to/out.c path/to/out.h HEX_DATA [HEX_RNG_SEED]'

	out_c = Path(sys.argv[1])
	out_h = Path(sys.argv[2])

	try:
		data = bytes.fromhex(sys.argv[3])
	except ValueError:
		return 'Invalid hex data'

	if len(sys.argv) == 5 and sys.argv[4]:
		seed = sys.argv[4]
	else:
		seed = urandom(8).hex()

	v = Verifier(out_c, out_h, data, seed)

	with out_c.open('w') as f:
		f.write('/* Auto-generated by gen_verifier.py */\n')
		f.write(f'/* Key : {data.hex()} */\n')
		f.write(f'/* Seed: {seed} */\n\n')
		f.write(v.gen_c_source())

	with out_h.open('w') as f:
		f.write('/* Auto-generated by gen_verifier.py */\n')
		f.write(f'/* Key : {data.hex()} */\n')
		f.write(f'/* Seed: {seed} */\n\n')
		f.write(v.gen_c_header())

	return 0


if __name__ == '__main__':
	sys.exit(main())
