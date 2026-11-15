#!/usr/bin/env python3
"""Check the byte-manipulation instructions in Ghidra's p-code emulator
against a Python model of the architecture manual's definitions.

usage: emutest.py [LANGUAGE_ID...]
"""
import random
import sys

import pyghidra

pyghidra.start()

from ghidra.app.emulator import EmulatorHelper
from ghidra.program.database import ProgramDB
from ghidra.program.model.lang import LanguageID
from ghidra.program.util import DefaultLanguageService
from ghidra.util.task import TaskMonitor
from java.lang import Object
from java.math import BigInteger

M = (1 << 64) - 1
PC = 0xffffffff00020000


def bmask(bits):
    return sum(0xff << (8 * i) for i in range(8) if bits & (1 << i))


W = {"B": 0xff, "W": 0xffff, "L": 0xffffffff, "Q": M}


def ext_l(w):
    return lambda a, b: (a >> ((b & 7) * 8)) & W[w]


def ext_h(w):
    return lambda a, b: (a << ((64 - (b & 7) * 8) & 63)) & W[w]


def ins_l(w):
    return lambda a, b: ((a & W[w]) << ((b & 7) * 8)) & M


def ins_h(w):
    return lambda a, b: ((a & W[w]) << ((b & 7) * 8)) >> 64


def msk_l(w):
    return lambda a, b: a & ~(W[w] << ((b & 7) * 8))


def msk_h(w):
    return lambda a, b: a & ~((W[w] << ((b & 7) * 8)) >> 64)


def cmpbge(a, b):
    return sum(1 << i for i in range(8) if ((a >> 8 * i) & 0xff) >= ((b >> 8 * i) & 0xff))


OPS = {  # name: (opcode, func, model)
    "CMPBGE": (0x10, 0x0f, cmpbge),
    "ZAP": (0x12, 0x30, lambda a, b: a & ~bmask(b)),
    "ZAPNOT": (0x12, 0x31, lambda a, b: a & bmask(b)),
}
for w, f in (("B", 0x06), ("W", 0x16), ("L", 0x26), ("Q", 0x36)):
    OPS["EXT%sL" % w] = (0x12, f, ext_l(w))
for w, f in (("W", 0x5a), ("L", 0x6a), ("Q", 0x7a)):
    OPS["EXT%sH" % w] = (0x12, f, ext_h(w))
for w, f in (("B", 0x0b), ("W", 0x1b), ("L", 0x2b), ("Q", 0x3b)):
    OPS["INS%sL" % w] = (0x12, f, ins_l(w))
for w, f in (("W", 0x57), ("L", 0x67), ("Q", 0x77)):
    OPS["INS%sH" % w] = (0x12, f, ins_h(w))
for w, f in (("B", 0x02), ("W", 0x12), ("L", 0x22), ("Q", 0x32)):
    OPS["MSK%sL" % w] = (0x12, f, msk_l(w))
for w, f in (("W", 0x52), ("L", 0x62), ("Q", 0x72)):
    OPS["MSK%sH" % w] = (0x12, f, msk_h(w))

# The byte-manipulation instructions are common to all processors, so one
# language per register naming variant is enough.
LANGS = ["21064:LE:64:vms", "21164:LE:64:unix", "21264:LE:64:nt"]

rng = random.Random(1)
A = [0x8877665544332211, 0, M, 0x0123456789abcdef] + [rng.getrandbits(64) for _ in range(4)]
B = list(range(8)) + [0xff, 0x5a, 0xa5, 0xf0, 0x0f, 0x80] + [rng.getrandbits(64) for _ in range(4)]


def run(lang_id):
    lang = DefaultLanguageService.getLanguageService().getLanguage(LanguageID(lang_id))
    consumer = Object()
    prog = ProgramDB("emutest", lang, lang.getDefaultCompilerSpec(), consumer)
    space = prog.getAddressFactory().getDefaultAddressSpace()
    tx = prog.startTransaction("setup")
    prog.getMemory().createInitializedBlock("text", space.getAddress(hex(PC)), 0x10000, 0,
                                            TaskMonitor.DUMMY, False)
    prog.endTransaction(tx, True)
    print(f"language {lang_id}")

    # Integer register n lives at offset 8*n; its name depends on the variant
    # (R1 for VMS, t0 for UNIX and NT).
    RA, RB, RC = (lang.getRegister(lang.getAddressFactory().getRegisterSpace(), 8 * n, 8)
                  for n in (1, 2, 3))

    fails = total = 0
    emu = EmulatorHelper(prog)
    for name, (opc, func, model) in OPS.items():
        bad = 0
        for lit in (False, True):
            for a in A:
                for b in B:
                    if lit:
                        b &= 0xff
                        insn = opc << 26 | 1 << 21 | b << 13 | 1 << 12 | func << 5 | 3
                    else:
                        insn = opc << 26 | 1 << 21 | 2 << 16 | func << 5 | 3
                    # The emulator caches decoded instructions by address, so
                    # every case gets an address of its own.
                    pc = PC + 4 * total
                    emu.writeMemory(space.getAddress(hex(pc)), insn.to_bytes(4, "little"))
                    emu.writeRegister(RA, BigInteger(str(a)))
                    emu.writeRegister(RB, BigInteger(str(b)))
                    emu.writeRegister(RC, BigInteger("12345"))
                    emu.writeRegister(emu.getPCRegister(), BigInteger(str(pc)))
                    emu.step(TaskMonitor.DUMMY)
                    got = int(str(emu.readRegister(RC))) & M
                    want = model(a, b)
                    total += 1
                    if got != want:
                        bad += 1
                        if bad <= 3:
                            print(f"  {name} {'lit' if lit else 'reg'} a={a:#x} b={b:#x}: "
                                  f"got {got:#x} want {want:#x}")
        fails += bad
        print(f"{name:7s} {'ok' if not bad else 'FAIL x%d' % bad}")
    emu.dispose()
    prog.release(consumer)
    print(f"FAILURES: {fails}/{total}")
    return fails


sys.exit(1 if sum(run(lang_id) for lang_id in sys.argv[1:] or LANGS) else 0)
