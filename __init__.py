from __future__ import print_function

import struct

import abc

from binaryninja import (
	Architecture, RegisterInfo, InstructionInfo,

	InstructionTextToken, InstructionTextTokenType,

	BranchType, CallingConvention,

	LowLevelILOperation, LLIL_TEMP,

	LowLevelILLabel,

	FlagRole,

	LowLevelILFlagCondition,

	log_error)
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.enums import (SegmentFlag, SymbolType)
import traceback

class VMNDHError(Exception):
	pass

ARCH_NAME = 'vmndh-2k12'

# Type 3 instructions are (un)conditional branches. They do not
# take any operands, as the branch targets are always immediates
# stored in the instruction itself.
BRANCH_INSTRUCTIONS = [
	'ja', 'jb', 'jmpl', 'jmps', 'jnz', 'jz'
]

# There are technically only four different operand modes, but
# certain mode/register combinations have different semantic
# meanings.
OP_FLAG_REG_REG                  = 0x00
OP_FLAG_REG_DIRECT08             = 0x01
OP_FLAG_REG_DIRECT16             = 0x02
OP_FLAG_REG                      = 0x03
OP_FLAG_DIRECT16                 = 0x04
OP_FLAG_DIRECT08                 = 0x05
OP_FLAG_REGINDIRECT_REG          = 0x06
OP_FLAG_REGINDIRECT_DIRECT08     = 0x07
OP_FLAG_REGINDIRECT_DIRECT16     = 0x08
OP_FLAG_REGINDIRECT_REGINDIRECT  = 0x09
OP_FLAG_REG_REGINDIRECT          = 0x0a

operand_lengths = {
	OP_FLAG_REG_REG                 : 2,
	OP_FLAG_REG_DIRECT08            : 2,
	OP_FLAG_REG_DIRECT16            : 3,
	OP_FLAG_REG                     : 1,
	OP_FLAG_DIRECT16                : 2,
	OP_FLAG_DIRECT08                : 1,
	OP_FLAG_REGINDIRECT_REG         : 2,
	OP_FLAG_REGINDIRECT_DIRECT08    : 2,
	OP_FLAG_REGINDIRECT_DIRECT16    : 3,
	OP_FLAG_REGINDIRECT_REGINDIRECT : 2,
	OP_FLAG_REG_REGINDIRECT         : 2,
}
flag_word_size = {
	OP_FLAG_REG_REG                 : 2,
	OP_FLAG_REG_DIRECT08            : 1,
	OP_FLAG_REG_DIRECT16            : 2,
	OP_FLAG_REG                     : 2,
	OP_FLAG_DIRECT16                : 2,
	OP_FLAG_DIRECT08                : 1,
	OP_FLAG_REGINDIRECT_REG         : 2,
	OP_FLAG_REGINDIRECT_DIRECT08    : 1,
	OP_FLAG_REGINDIRECT_DIRECT16    : 2,
	OP_FLAG_REGINDIRECT_REGINDIRECT : 2,
	OP_FLAG_REG_REGINDIRECT         : 2,
}

Registers = {
	0x00: 'r0',
	0x01: 'r1',
	0x02: 'r2',
	0x03: 'r3',
	0x04: 'r4',
	0x05: 'r5',
	0x06: 'r6',
	0x07: 'r7',
	0x08: 'sp',
	0x09: 'bp',
	0x0a: 'pc'
}

OperandTokens = [
	lambda dst, src: [    # OP_FLAG_REG_REG
		InstructionTextToken(InstructionTextTokenType.RegisterToken, Registers[dst]),
		InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "),
		InstructionTextToken(InstructionTextTokenType.RegisterToken, Registers[src])
	],
	lambda dst, src: [    # OP_FLAG_REG_DIRECT08
		InstructionTextToken(InstructionTextTokenType.RegisterToken, Registers[dst]),
		InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "),
		InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(src), src)
	],
	lambda dst, src: [    # OP_FLAG_REG_DIRECT16
		InstructionTextToken(InstructionTextTokenType.RegisterToken, Registers[dst]),
		InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "),
		InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(src), src)
	],
	lambda dst, src: [    # OP_FLAG_REG
		InstructionTextToken(InstructionTextTokenType.RegisterToken, Registers[dst])
	],
	lambda dst, src: [    # OP_FLAG_DIRECT16
		InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(dst), dst)
	],
	lambda dst, src: [    # OP_FLAG_DIRECT08
		InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(dst), dst)
	],
	lambda dst, src: [    # OP_FLAG_REGINDIRECT_REG
		InstructionTextToken(InstructionTextTokenType.TextToken, "["),
		InstructionTextToken(InstructionTextTokenType.RegisterToken, Registers[dst]),
		InstructionTextToken(InstructionTextTokenType.TextToken, "]"),
		InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "),
		InstructionTextToken(InstructionTextTokenType.RegisterToken, Registers[src])
	],
	lambda dst, src: [    # OP_FLAG_REGINDIRECT_DIRECT08
		InstructionTextToken(InstructionTextTokenType.TextToken, "["),
		InstructionTextToken(InstructionTextTokenType.RegisterToken, Registers[dst]),
		InstructionTextToken(InstructionTextTokenType.TextToken, "]"),
		InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "),
		InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(src), src)
	],
	lambda dst, src: [    # OP_FLAG_REGINDIRECT_DIRECT16
		InstructionTextToken(InstructionTextTokenType.TextToken, "["),
		InstructionTextToken(InstructionTextTokenType.RegisterToken, Registers[dst]),
		InstructionTextToken(InstructionTextTokenType.TextToken, "]"),
		InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "),
		InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(src), src)
	],
	lambda dst, src: [    # OP_FLAG_REGINDIRECT_REGINDIRECT
		InstructionTextToken(InstructionTextTokenType.TextToken, "["),
		InstructionTextToken(InstructionTextTokenType.RegisterToken, Registers[dst]),
		InstructionTextToken(InstructionTextTokenType.TextToken, "]"),
		InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "),
		InstructionTextToken(InstructionTextTokenType.TextToken, "["),
		InstructionTextToken(InstructionTextTokenType.RegisterToken, Registers[src]),
		InstructionTextToken(InstructionTextTokenType.TextToken, "]")
	],
	lambda dst, src: [    # OP_FLAG_REG_REGINDIRECT
		InstructionTextToken(InstructionTextTokenType.RegisterToken, Registers[dst]),
		InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "),
		InstructionTextToken(InstructionTextTokenType.TextToken, "["),
		InstructionTextToken(InstructionTextTokenType.RegisterToken, Registers[src]),
		InstructionTextToken(InstructionTextTokenType.TextToken, "]")
	],
]

SourceOperandsIL = [
	# OP_FLAG_REG_REG
	lambda il, value: il.reg(2, Registers[value]),
	# OP_FLAG_REG_DIRECT08
	lambda il, value: il.const(1, value),
	# OP_FLAG_REG_DIRECT16
	lambda il, value: il.const(2, value),
	# OP_FLAG_REG
	lambda il, value: None,
	# OP_FLAG_DIRECT16
	lambda il, value: None,
	# OP_FLAG_DIRECT08
	lambda il, value: None,
	# OP_FLAG_REGINDIRECT_REG
	lambda il, value: il.reg(1, Registers[value]),
	# OP_FLAG_REGINDIRECT_DIRECT08
	lambda il, value: il.const(1, value),
	# OP_FLAG_REGINDIRECT_DIRECT16
	lambda il, value: il.const(2, value),
	# OP_FLAG_REGINDIRECT_REGINDIRECT
	lambda il, value: il.load(1, il.reg(2, Registers[value])),
	# OP_FLAG_REG_REGINDIRECT
	lambda il, value: il.load(1, il.reg(2, Registers[value])),
]

# this is a kluge for it working on both dev and release for now
constant_attr_name = None

def get_constant_value(il_instr):
	global constant_attr_name
	if not constant_attr_name:
		constant_attr_name = "value"
		if hasattr(il_instr, "constant"):
			constant_attr_name = "constant"
	return getattr(il_instr, constant_attr_name)

def cond_branch(il, cond, dest, fail_addr):
	label = None
	if il[dest].operation == LowLevelILOperation.LLIL_CONST:
		label = il.get_label_for_address(Architecture[ARCH_NAME], get_constant_value(il[dest]))
	if label is None:
		label = LowLevelILLabel()
		indirect = True
	else:
		indirect = False
	f = il.get_label_for_address(Architecture[ARCH_NAME], fail_addr)
	if f is None:
		f = LowLevelILLabel()
		il.mark_label(f)
	il.append(il.if_expr(cond, label, f))
	if indirect:
		il.mark_label(label)
		il.append(il.jump(dest))

def jump(il, dest):
	label = None
	if il[dest].operation == LowLevelILOperation.LLIL_CONST:
		label = il.get_label_for_address(Architecture[ARCH_NAME], get_constant_value(il[dest]))
	if label is None:
		il.append(il.jump(dest))
	else:
		il.append(il.goto(label))

class Instruction(object):
	width = None
	src_value = None
	dst_value = None
	error = False
	flag_offset = 0
	length = 1
	def __init__(self, data, addr):
		self.parseWithFlagSet(data, addr)
		if hasattr(self, "init"):
			self.init(data, addr)
	def getName(self):
		return self.__class__.__name__.lower()
	def parseWithFlagSet(self, data, addr):
		if self.length == 1:
			return
		self.length = self.flag_offset+1+operand_lengths[self.flag]
		try:
			self.width = flag_word_size[self.flag]
		except KeyError:
			raise VMNDHError("Unknown flag %x in instr %s" % (self.flag, self.getName()))
		self.dst_value = ord(data[self.flag_offset+1])
		if self.flag in [OP_FLAG_DIRECT16, OP_FLAG_DIRECT08]:
			if self.flag == OP_FLAG_DIRECT16:
				self.dst_value = struct.unpack_from("<H", data, self.flag_offset+1)[0]
			return
		try:
			self.dst_reg = Registers[self.dst_value]
		except KeyError:
			raise VMNDHError("Destination register %x not valid" % self.dst_value)
		if self.flag == OP_FLAG_REG:
			return
		self.src_value = ord(data[self.flag_offset+2])
		if self.length == self.flag_offset+4:
			self.src_value = struct.unpack_from("<H", data, self.flag_offset+2)[0]
		else:
			if self.flag not in [OP_FLAG_REG_REG, OP_FLAG_REGINDIRECT_REG,
				OP_FLAG_REGINDIRECT_REGINDIRECT, OP_FLAG_REG_REGINDIRECT]:
				return
			if self.src_value not in Registers:
				raise VMNDHError("Source %x not a valid register" % self.src_value)

	def getTextToken(self):
		if not hasattr(self, "flag") or self.flag < 0 or self.flag > len(OperandTokens):
			return []
		return OperandTokens[self.flag](self.dst_value, self.src_value)
	def do_il(self, data, addr, il):
		return il.unimplemented()

class FlagInstruction(Instruction):
	def __init__(self, data, addr):
		self.length = 4
		self.flag = ord(data[1])
		try:
			self.length = 2 + operand_lengths[self.flag]
		except KeyError:
			raise VMNDHError("Flag %x not in operand_lengths" % self.flag)

		if self.flag not in self.valid_flags:
			raise VMNDHError("Flag %x not valid for instr %s" % (self.flag, self.getName()))

		self.flag_offset = 1
		Instruction.__init__(self, data, addr)

class SingleOpInstruction(Instruction):
	length = 2
	flag = OP_FLAG_REG

class DoubleOpInstruction(Instruction):
	length = 3
	flag = OP_FLAG_REG_REG

class BranchInstruction(Instruction):
	def init(self, data, addr):
		if self.flag != OP_FLAG_REG:
			self.dst_value += addr + self.length
			self.dst_value &= 0xffff

class Push(FlagInstruction):
	valid_flags = [OP_FLAG_REG, OP_FLAG_DIRECT08, OP_FLAG_DIRECT16]
	def do_il(self, data, addr, il):
		src = SourceOperandsIL[self.flag](il, self.src_value)
		if self.flag == OP_FLAG_REG:
			return il.push(2, il.reg(2, self.dst_reg))
		return il.push(2, il.const(2, self.dst_value))
class Nop(Instruction):
	def do_il(self, data, addr, il):
		return il.nop()
class Pop(SingleOpInstruction):
	def do_il(self, data, addr, il):
		return il.set_reg(2, self.dst_reg, il.pop(2))
class Mov(FlagInstruction):
	valid_flags = [
		OP_FLAG_REG_REG,
		OP_FLAG_REG_DIRECT08,
		OP_FLAG_REG_DIRECT16,
		OP_FLAG_REGINDIRECT_REG,
		OP_FLAG_REGINDIRECT_DIRECT08,
		OP_FLAG_REGINDIRECT_DIRECT16,
		OP_FLAG_REGINDIRECT_REGINDIRECT,
		OP_FLAG_REG_REGINDIRECT
	]
	def do_il(self, data, addr, il):
		src = SourceOperandsIL[self.flag](il, self.src_value)
		if self.flag in [OP_FLAG_REG_REG, OP_FLAG_REG_DIRECT08,
			OP_FLAG_REG_DIRECT16, OP_FLAG_REG_REGINDIRECT]:
			return il.set_reg(2, self.dst_reg, src)
		else:
			return il.store(2, il.reg(2, self.dst_reg), src)
class Add(FlagInstruction):
	valid_flags = [OP_FLAG_REG_REG, OP_FLAG_REG_DIRECT08, OP_FLAG_REG_DIRECT16]
	def do_il(self, data, addr, il):
		src = SourceOperandsIL[self.flag](il, self.src_value)
		return il.set_reg(2, self.dst_reg, il.add(2, il.reg(2, self.dst_reg), src, flags='z'))
class Sub(FlagInstruction):
	valid_flags = [OP_FLAG_REG_REG, OP_FLAG_REG_DIRECT08, OP_FLAG_REG_DIRECT16]
	def do_il(self, data, addr, il):
		src = SourceOperandsIL[self.flag](il, self.src_value)
		return il.set_reg(2, self.dst_reg, il.sub(2, il.reg(2, self.dst_reg), src, flags='z'))

class Mul(FlagInstruction):
	valid_flags = [OP_FLAG_REG_REG, OP_FLAG_REG_DIRECT08, OP_FLAG_REG_DIRECT16]
	def do_il(self, data, addr, il):
		src = SourceOperandsIL[self.flag](il, self.src_value)
		return il.set_reg(2, self.dst_reg, il.mult(2, il.reg(2, self.dst_reg), src, flags='z'))
class Div(FlagInstruction):
	valid_flags = [OP_FLAG_REG_REG, OP_FLAG_REG_DIRECT08, OP_FLAG_REG_DIRECT16]
	def do_il(self, data, addr, il):
		src = SourceOperandsIL[self.flag](il, self.src_value)
		return il.set_reg(2, self.dst_reg, il.div_unsigned(2, il.reg(2, self.dst_reg), src), flags='z')
class Inc(SingleOpInstruction):
	def do_il(self, data, addr, il):
		return il.set_reg(2, self.dst_reg, il.add(2, il.reg(2, self.dst_reg), il.const(2, 1)))
class Dec(SingleOpInstruction):
	def do_il(self, data, addr, il):
		return il.set_reg(2, self.dst_reg, il.sub(2, il.reg(2, self.dst_reg), il.const(2, 1)))
class Or(FlagInstruction):
	valid_flags = [OP_FLAG_REG_REG, OP_FLAG_REG_DIRECT08, OP_FLAG_REG_DIRECT16]
	def do_il(self, data, addr, il):
		src = SourceOperandsIL[self.flag](il, self.src_value)
		return il.set_reg(2, self.dst_reg, il.or_expr(2, il.reg(2, self.dst_reg), src, flags='z'))
class And(FlagInstruction):
	valid_flags = [OP_FLAG_REG_REG, OP_FLAG_REG_DIRECT08, OP_FLAG_REG_DIRECT16]
	def do_il(self, data, addr, il):
		src = SourceOperandsIL[self.flag](il, self.src_value)
		return il.set_reg(2, self.dst_reg, il.and_expr(2, il.reg(2, self.dst_reg), src, flags='z'))
class Xor(FlagInstruction):
	valid_flags = [OP_FLAG_REG_REG, OP_FLAG_REG_DIRECT08, OP_FLAG_REG_DIRECT16]
	def do_il(self, data, addr, il):
		src = SourceOperandsIL[self.flag](il, self.src_value)
		return il.set_reg(2, self.dst_reg, il.xor_expr(2, il.reg(2, self.dst_reg), src, flags='z'))
class Not(SingleOpInstruction):
	def do_il(self, data, addr, il):
		return il.set_reg(2, self.dst_reg, il.not_expr(2, il.reg(2, self.dst_reg), flags='z'))
class Jz(SingleOpInstruction, BranchInstruction):
	flag = OP_FLAG_DIRECT16
	def do_il(self, data, addr, il):
		cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_E), il.const(2, self.dst_value), addr+self.length)
class Jnz(SingleOpInstruction, BranchInstruction):
	flag = OP_FLAG_DIRECT16
	def do_il(self, data, addr, il):
		cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_NE), il.const(2, self.dst_value), addr+self.length)
class Jmps(SingleOpInstruction, BranchInstruction):
	flag = OP_FLAG_DIRECT08
	def do_il(self, data, addr, il):
		jump(il, il.const(1, self.dst_value))
class Test(DoubleOpInstruction):
	def do_il(self, data, addr, il):
		if self.dst_value == self.src_value:
			return il.set_flag('z', il.compare_equal(2, il.reg(2, Registers[self.src_value]), il.const(2, 0)))
		return [il.set_flag('z', il.and_expr(2, il.compare_equal(2, il.reg(2, Registers[self.src_value]), il.const(2, 0)),
			il.compare_equal(2, il.reg(2, self.dst_reg), il.const(2, 0))))]
class Cmp(FlagInstruction):
	valid_flags = [OP_FLAG_REG_REG, OP_FLAG_REG_DIRECT08, OP_FLAG_REG_DIRECT16]
	def do_il(self, data, addr, il):
		src = SourceOperandsIL[self.flag](il, self.src_value)
		return il.sub(2, il.reg(2, self.dst_reg), src, flags='*')
class Call(FlagInstruction, BranchInstruction):
	valid_flags = [OP_FLAG_REG, OP_FLAG_DIRECT16]
	def do_il(self, data, addr, il):
		rc = [] #[il.push(2, il.const(2, addr+self.length))]
		if self.flag == OP_FLAG_REG:
			return rc + [il.call(il.reg(2, self.dst_reg))]
		return rc + [il.call(il.const(2, self.dst_value))]

class Ret(Instruction):
	def do_il(self, data, addr, il):
		return il.ret(il.pop(2))

class Jmpl(SingleOpInstruction, BranchInstruction):
	flag = OP_FLAG_DIRECT16
	def do_il(self, data, addr, il):
		jump(il, il.const(2, self.dst_value))

class End(Instruction):
	def do_il(self, data, addr, il):
		return il.no_ret()
class Xchg(DoubleOpInstruction):
	def do_il(self, data, addr, il):
		src = SourceOperandsIL[self.flag](il, self.src_value)
		return [il.set_reg(2, LLIL_TEMP(0), src),
			il.set_reg(2, Registers[self.src_value], il.reg(2, Registers[self.dst_value])),
			il.set_reg(2, Registers[self.dst_value], il.reg(2, LLIL_TEMP(0)))]
class Ja(SingleOpInstruction, BranchInstruction):
	flag = OP_FLAG_DIRECT16
	def do_il(self, data, addr, il):
		cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_SGT), il.const(2, self.dst_value), addr+self.length)
class Jb(SingleOpInstruction, BranchInstruction):
	flag = OP_FLAG_DIRECT16
	def do_il(self, data, addr, il):
		cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_SLT), il.const(2, self.dst_value), addr+self.length)

class Syscall(Instruction):
	def do_il(self, data, addr, il):
		rc = [il.system_call()]
		# TODO: figure out how to noreturn on exit
		#if il.reg(2, 'r0') == il.const(2, 1):
		#	rc.append(il.no_ret())
		return rc


instruction_dict = {
	0x01: Push,
	0x02: Nop,
	0x03: Pop,
	0x04: Mov,
	0x06: Add,
	0x07: Sub,
	0x08: Mul,
	0x09: Div,
	0x0a: Inc,
	0x0b: Dec,
	0x0c: Or,
	0x0d: And,
	0x0e: Xor,
	0x0f: Not,
	0x10: Jz,
	0x11: Jnz,
	0x16: Jmps,
	0x17: Test,
	0x18: Cmp,
	0x19: Call,
	0x1a: Ret,
	0x1b: Jmpl,
	0x1c: End,
	0x1d: Xchg,
	0x1e: Ja,
	0x1f: Jb,
	0x30: Syscall,
}

mnemonics = {
	'push'    : '\x01',
	'nop'     : '\x02',
	'pop'     : '\x03',
	'mov'     : '\x04',
	'add'     : '\x06',
	'sub'     : '\x07',
	'mul'     : '\x08',
	'div'     : '\x09',
	'inc'     : '\x0a',
	'dec'     : '\x0b',
	'or'      : '\x0c',
	'and'     : '\x0d',
	'xor'     : '\x0e',
	'not'     : '\x0f',
	'jz'      : '\x10',
	'jnz'     : '\x11',
	'jmps'    : '\x16',
	'test'    : '\x17',
	'cmp'     : '\x18',
	'call'    : '\x19',
	'ret'     : '\x1a',
	'jmpl'    : '\x1b',
	'end'     : '\x1c',
	'xchg'    : '\x1d',
	'ja'      : '\x1e',
	'jb'      : '\x1f',
	'syscall' : '\x30',
}
register_indexes = {
	'r0': '\x00',
	'r1': '\x01',
	'r2': '\x02',
	'r3': '\x03',
	'r4': '\x04',
	'r5': '\x05',
	'r6': '\x06',
	'r7': '\x07',
	'sp': '\x08',
	'bp': '\x09',
	'pc': '\x0a',
}

class VMNDH(Architecture):
	name = 'vmndh-2k12'
	address_size = 2
	default_int_size = 2
	max_instr_length = 5

	regs = {
		'r0': RegisterInfo('r0', 2),
		'r1': RegisterInfo('r1', 2),
		'r2': RegisterInfo('r2', 2),
		'r3': RegisterInfo('r3', 2),
		'r4': RegisterInfo('r4', 2),
		'r5': RegisterInfo('r5', 2),
		'r6': RegisterInfo('r6', 2),
		'r7': RegisterInfo('r7', 2),
		'sp': RegisterInfo('sp', 2),
		'bp': RegisterInfo('bp', 2),
		'pc': RegisterInfo('pc', 2),
	}

	flags = ['a', 'b', 'z']

	# The first flag write type is ignored currently.
	# See: https://github.com/Vector35/binaryninja-api/issues/513
	flag_write_types = ['', '*', 'a', 'b', 'z']

	flags_written_by_flag_write_type = {
		'*': ['a', 'b', 'z'],
		'z': ['z']
		}
	flag_roles = {
		'a': FlagRole.CarryFlagRole,
		'b': FlagRole.NegativeSignFlagRole,
		'z': FlagRole.ZeroFlagRole,
		#'v': FlagRole.OverflowFlagRole
	}

	# WHAT IS THIS????
	flags_required_for_flag_condition = {
#		LowLevelILFlagCondition.LLFC_UGE: ['c'],
#		LowLevelILFlagCondition.LLFC_ULT: ['c'],
		LowLevelILFlagCondition.LLFC_SGT: ['a'],
		LowLevelILFlagCondition.LLFC_SLT: ['b'],
		LowLevelILFlagCondition.LLFC_E:   ['z'],
		LowLevelILFlagCondition.LLFC_NE:  ['z'],
#		LowLevelILFlagCondition.LLFC_NEG: ['n'],
#		LowLevelILFlagCondition.LLFC_POS: ['n']
	}

	stack_pointer = 'sp'

	def perform_is_never_branch_patch_available(self, data, addr):
		return ord(data[0]) in [0x10, 0x11, 0x16, 0x1b, 0x1e, 0x1f]

	def perform_is_invert_branch_patch_available(self, data, addr):
		return ord(data[0]) in [0x10, 0x11, 0x1e, 0x1f]

	def perform_is_always_branch_patch_available(self, data, addr):
		return ord(data[0]) in [0x10, 0x11, 0x1e, 0x1f]

	def perform_is_skip_and_return_zero_patch_available(self, data, addr):
		return (data[0] == "\x19") and (len(data) == 4)

	def perform_is_skip_and_return_value_patch_available(self, data, addr):
		return (data[0] == "\x19") and (len(data) == 4)

	def perform_convert_to_nop(self, data, addr):
		return "\x02" * len(data)

	def perform_never_branch(self, data, addr):
		return self.perform_convert_to_nop(data, addr)

	def perform_always_branch(self, data, addr):
		if ord(data[0]) not in [0x10, 0x11, 0x1e, 0x1f]:
			return None
		return "\x1b" + data[1:]

	def perform_invert_branch(self, data, addr):
		if ord(data[0]) not in [0x10, 0x11, 0x1e, 0x1f]:
			return None
		return chr(ord(data[0]) ^ 0x01) + data[1:]

	def perform_skip_and_return_value(self, data, addr, value):
		if (data[0] != "\x19") or (len(data) != 4):
			return None
		return "\x04" + chr(OP_FLAG_REG_DIRECT08) + "\x00" + chr(value & 0xff)

	def perform_assemble(self, code, addr):
		if ".b" in code:
			code = code.replace(".b", "")
		code = filter(None, code.replace(", ", " ").split(" "))
		mnemonic = code[0]
		if mnemonic not in mnemonics:
			return (None, "Invalid mnemonic %s" % code)
		assembly = mnemonics[mnemonic]
		cls = instruction_dict[ord(assembly)]
		if cls.__base__ == Instruction:
			return (assembly, "")
		valid_flags = None
		if FlagInstruction in cls.__mro__:
			valid_flags = cls.valid_flags
		else:
			valid_flags = [cls.flag]

		dst_flag = None
		dst = code[1]
		if dst[0] == '[' and dst[-1] == ']':
			if OP_FLAG_REGINDIRECT_REG not in valid_flags:
				return (None, "Invalid destination operand %s" % dst)
			dst = dst[1:-1]
			dst_flag = OP_FLAG_REGINDIRECT_REG

		try:
			dst_value = int(dst, 0) & 0xffff
			if dst_value < 0x100:
				flag = OP_FLAG_DIRECT08
				dst = struct.pack("B", dst_value)
			else:
				if BranchInstruction in cls.__mro__:
					dst_value -= addr
					if mnemonic == 'jns':
						dst_value -= 2
					elif mnemonic == 'call':
						dst_value -= 4
					else:
						dst_value -= 3
					dst_value &= 0xffff
				flag = OP_FLAG_DIRECT16
				dst = struct.pack("<H", dst_value)
		except:
			dst = register_indexes[dst]
			flag = OP_FLAG_REG

		if len(code) == 2:
			if flag not in valid_flags:
				return (None, "Invalid destination operand %s" % dst)
			if len(valid_flags) > 1:
				assembly += chr(flag)
			assembly += dst
			return (assembly, "")

		src_flag = None
		src = code[2]
		if src[0] == '[' and src[-1] == ']':
			if OP_FLAG_REG_REGINDIRECT not in valid_flags:
				return (None, "Invalid destination operand %s" % dst)
			src = src[1:-1]
			src_flag = OP_FLAG_REGINDIRECT_REG

		if flag != OP_FLAG_REG:
			return (None, "Invalid destination register: %s" % dst)

		flag = None

		if not src_flag:
			try:
				src_value = int(src, 0) & 0xffff
				if src_value < 0x100:
					src_flag = OP_FLAG_DIRECT08
					src = struct.pack("B", src_value)
				else:
					src_flag = OP_FLAG_DIRECT16
					src = struct.pack("<H", src_value)
			except:
				src = register_indexes[src]
				src_flag = OP_FLAG_REG

		if dst_flag:
			if src_flag == dst_flag:
				flag = OP_FLAG_REGINDIRECT_REGINDIRECT
			elif src_flag == OP_FLAG_DIRECT08:
				flag = OP_FLAG_REGINDIRECT_DIRECT08
			elif src_flag == OP_FLAG_DIRECT16:
				flag = OP_FLAG_REGINDIRECT_DIRECT16
			elif src_flag == OP_FLAG_REG:
				flag = OP_FLAG_REGINDIRECT_REG
			else:
				return (None, "src_flag is bugged: %x" % src_flag)
		else:
			if src_flag == OP_FLAG_REGINDIRECT_REG:
				flag = OP_FLAG_REG_REGINDIRECT
			elif src_flag == OP_FLAG_DIRECT08:
				flag = OP_FLAG_REG_DIRECT08
			elif src_flag == OP_FLAG_DIRECT16:
				flag = OP_FLAG_REG_DIRECT16
			elif src_flag == OP_FLAG_REG:
				flag = OP_FLAG_REG_REG
			else:
				return (None, "src_flag is bugged: %x" % src_flag)

		if flag not in valid_flags:
			return (None, "Invalid operands for operation: %s" % mnemonic)

		if len(valid_flags) > 1:
			assembly += chr(flag)
		assembly += dst + src
		return (assembly, None)

	def decode_instruction(self, data, addr):
		if addr < 0x8000:
			return
		opcode = ord(data[0])
		if opcode not in instruction_dict:
			log_error('[{:x}] Bad opcode: {:x}'.format(addr, opcode))
			return None

		instr_obj = None
		try:
			instr_obj = instruction_dict[opcode](data, addr)
		except VMNDHError as e:
			log_error('[{:x}] Bad instruction: {:s}'.format(addr, e))
			return None

		return instr_obj

	def perform_get_instruction_info(self, data, addr):
		instr_obj = self.decode_instruction(data, addr)

		if not instr_obj or instr_obj.error:
			return None

		result = InstructionInfo()
		result.length = instr_obj.length

		instr_name = instr_obj.getName()

		# TODO: update this properly
		# Add branches
		if instr_name in ['ret', 'end']:
			result.add_branch(BranchType.FunctionReturn)
		elif instr_name.startswith('jmp'):
			result.add_branch(BranchType.UnconditionalBranch, instr_obj.dst_value)
		elif instr_name in BRANCH_INSTRUCTIONS:
			result.add_branch(BranchType.TrueBranch, instr_obj.dst_value)
			result.add_branch(BranchType.FalseBranch, addr + instr_obj.length)
		elif instr_name == 'call':
			result.add_branch(BranchType.CallDestination, instr_obj.dst_value)
		elif instr_name == 'syscall':
			result.add_branch(BranchType.SystemCall)

		return result

	def perform_get_instruction_text(self, data, addr):
		instr_obj = self.decode_instruction(data, addr)

		if not instr_obj or instr_obj.error:
			return None

		tokens = []

		instruction_text = instr_obj.getName()

		if instr_obj.width == 1:
			instruction_text += '.b'

		tokens = [
			InstructionTextToken(InstructionTextTokenType.InstructionToken, '{:7s}'.format(instruction_text))
		]

		tokens += instr_obj.getTextToken()

		return tokens, instr_obj.length

	def perform_get_instruction_low_level_il(self, data, addr, il):
		instr_obj = self.decode_instruction(data, addr)

		if not instr_obj or instr_obj.error:
			return None

		insns = instr_obj.do_il(data, addr, il)
		if isinstance(insns, list):
			[il.append(i) for i in insns]
		elif insns is not None:
			try:
				il.append(insns)
			except:
				traceback.print_exc()
				print(type(insns), insns, instr_obj.getName(), hex(addr))
		return instr_obj.length

class VMNDHView(BinaryView):
	name = "VMNDH"
	long_name = "VMNDH Binary View"

	def __init__(self, data):
		BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
		self.platform = Architecture['vmndh-2k12'].standalone_platform

	@classmethod
	def is_valid_for_data(self, data):
		hdr = data.read(0, 6)
		if len(hdr) < 6:
			return False
		if hdr[:4] != ".NDH":
			return False
		return True

	def init(self):
		try:
			hdr = self.parent_view.read(4, 2)
			self.binary_length = struct.unpack("<H", hdr)[0]

			# Add mapping for RAM and hardware registers, not backed by file contents
			self.add_auto_segment(0x8000, self.binary_length, 6, self.binary_length,
				SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable)
			self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x8000, "main"))

			self.add_entry_point(0x8000)

			return True
		except:
			traceback.print_exc()
			print("ERROR!!!")
			log_error(traceback.format_exc())
			return False

	def perform_is_executable(self):
		return True

	def perform_get_entry_point(self):
		return 0x8000

class DefaultCallingConvention(CallingConvention):
	name = 'default'
	int_arg_regs = ('r0', 'r1')
	int_return_reg = 'r0'

VMNDHView.register()
VMNDH.register()

arch = Architecture[ARCH_NAME]
arch.register_calling_convention(DefaultCallingConvention(arch))
#BinaryViewType['VMNDH'].register_arch(23, Endianness.LittleEndian, arch)
