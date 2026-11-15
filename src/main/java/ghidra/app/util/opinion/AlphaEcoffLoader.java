/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.opinion;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Tru64 UNIX (Digital UNIX, DEC OSF/1) Alpha ECOFF executables and
 * shared libraries.
 *
 * <p>Function starts come from the ECOFF symbol table when present, from
 * .dynsym, and from the code range descriptors in .pdata. Each import gets
 * an external function. Its GOT slot points at a thunk for it and carries an
 * external reference, which is what lets the decompiler name calls through
 * the GOT, and its lazy-binding stub in .text becomes a thunk too.
 *
 * <p>GP is set in the program context where it is known on entry: past an
 * ldgp prologue, where local callers branch in, and at static procedures
 * without one, which run on their callers' GP.
 */
public class AlphaEcoffLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Alpha ECOFF (Tru64 UNIX)";

	private static final int ALPHAMAGIC = 0x183;
	private static final int FILHSZ = 24;
	private static final int AOUTHSZ = 80;
	private static final int SCNHSZ = 64;

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() < FILHSZ + AOUTHSZ) {
			return specs;
		}
		BinaryReader r = new BinaryReader(provider, true);
		if (r.readUnsignedShort(0) != ALPHAMAGIC || r.readUnsignedShort(20) < AOUTHSZ) {
			return specs;
		}
		long textStart = r.readLong(FILHSZ + 40);
		for (LanguageDescription ld : getLanguageService().getLanguageDescriptions(false)) {
			String id = ld.getLanguageID().getIdAsString();
			if (!ld.getProcessor().toString().equals("Alpha") || !id.endsWith(":unix")) {
				continue;
			}
			for (CompilerSpecDescription cs : ld.getCompatibleCompilerSpecDescriptions()) {
				specs.add(new LoadSpec(this, textStart,
					new LanguageCompilerSpecPair(ld.getLanguageID(), cs.getCompilerSpecID()),
					id.startsWith("21264:")));
			}
		}
		return specs;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		new Image(program, settings.provider(), settings.log(), settings.monitor()).load();
	}

	private record Section(String name, long vaddr, long size, long scnptr) {
	}

	private static class Image {
		// ECOFF symbol types (st) and storage classes (sc).
		static final int ST_GLOBAL = 1, ST_STATIC = 2, ST_PROC = 6, ST_STATICPROC = 14;
		static final int SC_TEXT = 1, SC_UNDEFINED = 6, SC_INIT = 22, SC_FINI = 26;
		static final Set<Integer> SC_ADDRESS = Set.of(1, 2, 3, 13, 14, 15, 22, 24, 25, 26, 27);

		// .dynsym section indices and the MIPS-style .dynamic tags Tru64 uses.
		static final int SHN_UNDEF = 0, SHN_TEXT = 0xff01;
		static final int STT_FUNC = 2;
		static final int UNOP = 0x2ffe0000;
		static final int DT_MIPS_LOCAL_GOTNO = 0x7000000a, DT_MIPS_GOTSYM = 0x70000013;

		final Program program;
		final BinaryReader r;
		final MessageLog log;
		final TaskMonitor monitor;
		final AddressSpace space;
		final Memory memory;
		final SymbolTable symbols;
		final Register gpReg;
		final Map<String, Section> sections = new LinkedHashMap<>();

		Image(Program program, ByteProvider provider, MessageLog log, TaskMonitor monitor) {
			this.program = program;
			this.r = new BinaryReader(provider, true);
			this.log = log;
			this.monitor = monitor;
			this.space = program.getAddressFactory().getDefaultAddressSpace();
			this.memory = program.getMemory();
			this.symbols = program.getSymbolTable();
			this.gpReg = program.getLanguage()
					.getRegister(program.getAddressFactory().getRegisterSpace(), 29 * 8, 8);
		}

		Address addr(long offset) {
			return space.getAddress(offset);
		}

		void load() throws IOException, CancelledException {
			int nscns = r.readUnsignedShort(2);
			long symptr = r.readLong(8);
			int opthdr = r.readUnsignedShort(20);
			long entry = r.readLong(FILHSZ + 32);
			long dataStart = r.readLong(FILHSZ + 48);
			long gp = r.readLong(FILHSZ + 72);

			for (int i = 0; i < nscns; i++) {
				long o = FILHSZ + opthdr + (long) i * SCNHSZ;
				String name = r.readAsciiString(o, 8).trim();
				sections.put(name, new Section(name, r.readLong(o + 16), r.readLong(o + 24),
					r.readLong(o + 32)));
			}
			createBlocks(dataStart);

			if (symptr != 0) {
				loadEcoffSymbols(symptr);
			}
			loadDynamic();
			loadPdata();

			if (gp != 0) {
				label(gp, "_gp", false);
			}
			Address entryAddr = addr(entry);
			symbols.addExternalEntryPoint(entryAddr);
			if (program.getFunctionManager().getFunctionAt(entryAddr) == null) {
				AbstractProgramLoader.markAsFunction(program, "entry", entryAddr);
			}
		}

		void createBlocks(long dataStart) throws IOException, CancelledException {
			FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, r.getByteProvider(),
				monitor);
			for (Section s : sections.values()) {
				if (s.vaddr() == 0 || s.size() == 0) {
					continue;
				}
				boolean exec = s.name().equals(".text") || s.name().equals(".init") ||
					s.name().equals(".fini");
				// Leave .got read-only so the decompiler folds loads from it.
				boolean write = s.vaddr() >= dataStart && !s.name().equals(".got") &&
					!s.name().equals(".rdata") && !s.name().equals(".rconst");
				try {
					if (s.scnptr() == 0) {
						MemoryBlockUtils.createUninitializedBlock(program, false, s.name(),
							addr(s.vaddr()), s.size(), null, NAME, true, write, exec, log);
					}
					else {
						MemoryBlockUtils.createInitializedBlock(program, false, s.name(),
							addr(s.vaddr()), fileBytes, s.scnptr(), s.size(), null, NAME, true,
							write, exec, log);
					}
				}
				catch (Exception e) {
					log.appendMsg("Skipping section " + s.name() + ": " + e.getMessage());
				}
			}
		}

		void label(long offset, String name, boolean function) {
			Address a = addr(offset);
			if (name.isEmpty() || !memory.contains(a)) {
				return;
			}
			try {
				symbols.createLabel(a, name, SourceType.IMPORTED);
				if (function) {
					AbstractProgramLoader.markAsFunction(program, name, a);
				}
			}
			catch (Exception e) {
				log.appendMsg("Cannot label " + a + " " + name + ": " + e.getMessage());
			}
		}

		/** The symbolic header (HDRR), external symbols and per-file local symbols. */
		void loadEcoffSymbols(long hdr) throws IOException {
			if (r.readUnsignedShort(hdr) != 0x1992) {
				log.appendMsg("Bad ECOFF symbolic header magic");
				return;
			}
			int ifdMax = r.readInt(hdr + 36);
			int iextMax = r.readInt(hdr + 44);
			long cbSymOffset = r.readLong(hdr + 48 + 4 * 8);
			long cbSsOffset = r.readLong(hdr + 48 + 7 * 8);
			long cbSsExtOffset = r.readLong(hdr + 48 + 8 * 8);
			long cbFdOffset = r.readLong(hdr + 48 + 9 * 8);
			long cbExtOffset = r.readLong(hdr + 48 + 11 * 8);

			for (int i = 0; i < iextMax; i++) {
				long o = cbExtOffset + 24L * i;
				ecoffSymbol(r.readLong(o), r.readAsciiString(cbSsExtOffset + r.readInt(o + 8)),
					r.readInt(o + 12));
			}
			for (int f = 0; f < ifdMax; f++) {
				long fd = cbFdOffset + 96L * f;
				int issBase = r.readInt(fd + 36);
				int isymBase = r.readInt(fd + 40);
				int csym = r.readInt(fd + 44);
				for (int k = 0; k < csym; k++) {
					long o = cbSymOffset + 16L * (isymBase + k);
					int bits = r.readInt(o + 12);
					int st = bits & 0x3f;
					if (st == ST_STATIC || st == ST_STATICPROC || st == ST_PROC) {
						ecoffSymbol(r.readLong(o),
							r.readAsciiString(cbSsOffset + issBase + r.readInt(o + 8)), bits);
					}
				}
			}
		}

		void ecoffSymbol(long value, String name, int bits) {
			int st = bits & 0x3f;
			int sc = (bits >>> 6) & 0x1f;
			boolean proc = st == ST_PROC || st == ST_STATICPROC;
			if (proc && sc == SC_UNDEFINED) {
				// A lazy-binding stub in .text for an import.
				label(value, name, true);
			}
			else if ((proc || st == ST_GLOBAL || st == ST_STATIC) && SC_ADDRESS.contains(sc)) {
				label(value, name, proc && (sc == SC_TEXT || sc == SC_INIT || sc == SC_FINI));
			}
		}

		/** .dynsym names, and external thunks for the imports in the GOT. */
		void loadDynamic() throws IOException {
			Section dynamic = sections.get(".dynamic");
			Section dynsym = sections.get(".dynsym");
			Section dynstr = sections.get(".dynstr");
			Section got = sections.get(".got");
			if (dynamic == null || dynsym == null || dynstr == null) {
				return;
			}

			// Each GOT has a pair of tags: the GOT index of its first global
			// entry, and the first .dynsym index those entries cover.
			List<Long> gotIndex = new ArrayList<>();
			List<Long> gotSym = new ArrayList<>();
			for (long o = dynamic.scnptr(); o < dynamic.scnptr() + dynamic.size(); o += 16) {
				int tag = r.readInt(o);
				long val = r.readUnsignedInt(o + 8);
				if (tag == 0) {
					break;
				}
				if (tag == DT_MIPS_LOCAL_GOTNO) {
					gotIndex.add(val);
				}
				else if (tag == DT_MIPS_GOTSYM) {
					gotSym.add(val);
				}
			}

			ExternalManager ext = program.getExternalManager();

			int nsyms = (int) (dynsym.size() / 24);
			Map<Long, Address> stubs = findStubs();
			Address thunks = null;
			Map<Address, ExternalLocation> imports = new HashMap<>();
			Set<String> noReturn = noReturnNames();
			for (int j = 0; j < nsyms; j++) {
				long o = dynsym.scnptr() + 24L * j;
				String name = r.readAsciiString(dynstr.scnptr() + r.readUnsignedInt(o));
				long value = r.readLong(o + 8);
				int info = r.readUnsignedByte(o + 20);
				int shndx = r.readUnsignedShort(o + 22);
				if (name.isEmpty() || name.startsWith(".")) {
					continue;
				}
				if (shndx != SHN_UNDEF) {
					label(value, name, shndx == SHN_TEXT && (info & 0xf) == STT_FUNC);
					continue;
				}
				// Imports below the first GOT symbol have no slot and are
				// reached only through their stubs.
				long slot = gotSlot(j, gotIndex, gotSym);
				boolean inGot = got != null && slot >= 0 && slot < got.size() / 8;
				Address stub = stubs.get((long) j);
				if (!inGot && stub == null) {
					continue;
				}
				ExternalLocation loc;
				try {
					loc = ext.addExtFunction(Library.UNKNOWN, name, null, SourceType.IMPORTED);
				}
				catch (Exception e) {
					log.appendMsg("Cannot create import " + name + ": " + e.getMessage());
					continue;
				}
				if (noReturn.contains(name.replaceFirst("^_+", ""))) {
					loc.getFunction().setNoReturn(true);
				}
				if (stub != null) {
					thunk(stub, 16, loc);
				}
				if (!inGot) {
					continue;
				}
				if (thunks == null) {
					thunks = createExternalBlock(nsyms);
					if (thunks == null) {
						return;
					}
				}
				Address thunk = thunks.add(8L * j);
				thunk(thunk, 1, loc);
				Address slotAddr = addr(got.vaddr() + 8 * slot);
				try {
					memory.setLong(slotAddr, thunk.getOffset());
					imports.put(slotAddr, loc);
				}
				catch (Exception e) {
					log.appendMsg("Cannot patch GOT slot " + slotAddr + ": " + e.getMessage());
				}
			}

			if (got != null) {
				for (long a = got.vaddr(); a < got.vaddr() + got.size(); a += 8) {
					try {
						DataUtilities.createData(program, addr(a), PointerDataType.dataType, 8,
							ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
					}
					catch (Exception e) {
						// leave it undefined
					}
				}
			}

			// The decompiler names a call through a pointer only when the
			// pointer's primary reference is external, as for a PE import table.
			ReferenceManager refs = program.getReferenceManager();
			for (Map.Entry<Address, ExternalLocation> e : imports.entrySet()) {
				refs.removeAllReferencesFrom(e.getKey());
				try {
					refs.addExternalReference(e.getKey(), 0, e.getValue(), SourceType.IMPORTED,
						RefType.DATA);
				}
				catch (InvalidInputException x) {
					log.appendMsg("Cannot reference import at " + e.getKey() + ": " +
						x.getMessage());
				}
			}
		}

		/**
		 * The noreturn analyzer keys its name lists by executable format and
		 * has none for ECOFF, so mark imports from the ELF list here.
		 */
		Set<String> noReturnNames() {
			Set<String> names = new HashSet<>();
			try (InputStream in = Application
					.getModuleDataFile("Base", "ElfFunctionsThatDoNotReturn")
					.getInputStream()) {
				for (String line : new String(in.readAllBytes()).split("\n")) {
					line = line.trim();
					if (!line.isEmpty() && !line.startsWith("#")) {
						names.add(line);
					}
				}
			}
			catch (IOException e) {
				log.appendMsg("Cannot read the non-returning function names: " + e.getMessage());
			}
			return names;
		}

		/**
		 * Lazy-binding stubs pass the .dynsym index of their import to the
		 * resolver, which the first GOT entry holds:
		 *
		 *     ldq  t12, -32752(gp)
		 *     lda  at, lo(zero)
		 *     ldah at, hi(at)
		 *     jmp  (t12)
		 */
		Map<Long, Address> findStubs() throws IOException {
			Map<Long, Address> stubs = new HashMap<>();
			Section text = sections.get(".text");
			if (text == null || text.scnptr() == 0) {
				return stubs;
			}
			for (long o = 0; o + 16 <= text.size(); o += 4) {
				long p = text.scnptr() + o;
				int lda = r.readInt(p + 4);
				int ldah = r.readInt(p + 8);
				if (r.readInt(p) == 0xa77d8010 && (lda & 0xffff0000) == 0x239f0000 &&
					(ldah & 0xffff0000) == 0x279c0000 && r.readInt(p + 12) == 0x6b7b0000) {
					stubs.put((long) (short) lda + ((long) (short) ldah << 16),
						addr(text.vaddr() + o));
				}
			}
			return stubs;
		}

		static long gotSlot(int sym, List<Long> gotIndex, List<Long> gotSym) {
			for (int k = Math.min(gotIndex.size(), gotSym.size()) - 1; k >= 0; k--) {
				if (sym >= gotSym.get(k)) {
					return gotIndex.get(k) + sym - gotSym.get(k);
				}
			}
			return -1;
		}

		Address createExternalBlock(int nsyms) {
			long end = 0;
			for (MemoryBlock b : memory.getBlocks()) {
				end = Math.max(end, b.getEnd().getOffset() + 1);
			}
			Address start = addr((end + 0xfff) & ~0xfffL);
			MemoryBlock b = MemoryBlockUtils.createUninitializedBlock(program, false,
				MemoryBlock.EXTERNAL_BLOCK_NAME, start, 8L * nsyms,
				"Thunks for imported functions", NAME, true, false, false, log);
			if (b != null) {
				b.setArtificial(true);
			}
			return b == null ? null : start;
		}

		void thunk(Address a, int len, ExternalLocation loc) {
			if (!memory.contains(a)) {
				return;
			}
			try {
				Function f = program.getFunctionManager().getFunctionAt(a);
				if (f == null) {
					f = program.getFunctionManager()
							.createFunction(loc.getLabel(), a,
								new AddressSet(a, a.add(len - 1)), SourceType.IMPORTED);
				}
				f.setThunkedFunction(loc.getFunction());
			}
			catch (Exception e) {
				log.appendMsg("Cannot create thunk at " + a + ": " + e.getMessage());
			}
		}

		/**
		 * Each code range descriptor in .pdata is a begin address relative to
		 * the start of .pdata and a self-relative runtime procedure descriptor
		 * offset. Ranges that continue a procedure set bit 0 of either word.
		 */
		void loadPdata() throws IOException {
			Section pdata = sections.get(".pdata");
			if (pdata == null || pdata.scnptr() == 0) {
				return;
			}
			TreeMap<Address, Long> gps = new TreeMap<>();
			Map<Address, Ldgp> prologues = new HashMap<>();
			for (long i = 0; i < pdata.size() / 8; i++) {
				int begin = r.readInt(pdata.scnptr() + 8 * i);
				int rpd = r.readInt(pdata.scnptr() + 8 * i + 4);
				if ((begin & 1) != 0 || (rpd & 1) != 0) {
					continue;
				}
				// The table ends with a zero entry, which would land on .pdata.
				Address a = addr(pdata.vaddr() + (begin & ~3));
				MemoryBlock block = memory.getBlock(a);
				if (block != null && block.isExecute()) {
					AbstractProgramLoader.markAsFunction(program, null, a);
					Ldgp p = ldgp(a);
					gps.put(a, p == null ? null : p.gp());
					if (p != null) {
						prologues.put(a, p);
					}
				}
			}

			Map<Address, List<Address>> branches = branches();
			inheritGp(gps, branches);
			for (Map.Entry<Address, Ldgp> e : prologues.entrySet()) {
				localEntry(e.getKey(), e.getValue(), branches.keySet());
			}
		}

		/** Sources of BR and BSR in .text, by target. */
		Map<Address, List<Address>> branches() throws IOException {
			Map<Address, List<Address>> branches = new HashMap<>();
			Section text = sections.get(".text");
			if (text == null || text.scnptr() == 0) {
				return branches;
			}
			for (long o = 0; o + 4 <= text.size(); o += 4) {
				int w = r.readInt(text.scnptr() + o);
				int op = w >>> 26;
				if (op == 0x30 || op == 0x34) {
					Address to = addr(text.vaddr() + o + 4 + 4L * ((w << 11) >> 11));
					branches.computeIfAbsent(to, k -> new ArrayList<>())
							.add(addr(text.vaddr() + o));
				}
			}
			return branches;
		}

		/** The GP an ldgp prologue sets up, and the address after it. */
		record Ldgp(long gp, Address end) {
		}

		/**
		 * The ldgp prologue at entry, or null if there is none:
		 *
		 *     ldah gp, hi(pv)
		 *     lda  gp, lo(gp)
		 *
		 * possibly padded with unops.
		 */
		Ldgp ldgp(Address entry) {
			try {
				int w = memory.getInt(entry);
				if ((w & 0xffff0000) != 0x27bb0000) {
					return null;
				}
				long gp = entry.getOffset() + ((long) (short) w << 16);
				Address a = entry.add(4);
				while (memory.getInt(a) == UNOP) {
					a = a.add(4);
				}
				w = memory.getInt(a);
				return (w & 0xffff0000) == 0x23bd0000 ? new Ldgp(gp + (short) w, a.add(4)) : null;
			}
			catch (Exception e) {
				return null;
			}
		}

		void setGp(Address a, long gp) throws ContextChangeException {
			program.getProgramContext().setValue(gpReg, a, a, BigInteger.valueOf(gp));
		}

		/**
		 * Static procedures without a prologue run on their callers' GP. Give
		 * one the GP of the procedures that branch to it when those with a
		 * known GP agree, and repeat until nothing changes.
		 */
		void inheritGp(TreeMap<Address, Long> gps, Map<Address, List<Address>> branches) {
			boolean changed = true;
			while (changed) {
				changed = false;
				for (Map.Entry<Address, Long> e : gps.entrySet()) {
					List<Address> from = branches.get(e.getKey());
					if (e.getValue() != null || from == null) {
						continue;
					}
					Set<Long> callers = new HashSet<>();
					for (Address f : from) {
						Map.Entry<Address, Long> caller = gps.floorEntry(f);
						if (caller != null && caller.getValue() != null) {
							callers.add(caller.getValue());
						}
					}
					if (callers.size() != 1) {
						continue;
					}
					long gp = callers.iterator().next();
					try {
						setGp(e.getKey(), gp);
						e.setValue(gp);
						changed = true;
					}
					catch (ContextChangeException x) {
						log.appendMsg("Cannot set GP at " + e.getKey() + ": " + x.getMessage());
					}
				}
			}
		}

		/**
		 * Callers that share a procedure's GP branch past its ldgp prologue.
		 * When something branches there, make that the function, with GP known
		 * on entry, and the outer entry a thunk to it.
		 */
		void localEntry(Address entry, Ldgp p, Set<Address> targets) {
			try {
				Address local = p.end();
				while (!targets.contains(local) && memory.getInt(local) == UNOP) {
					local = local.add(4);
				}
				if (!targets.contains(local)) {
					return;
				}
				setGp(local, p.gp());
				Symbol sym = symbols.getPrimarySymbol(entry);
				String name = sym == null || sym.getSource() == SourceType.DEFAULT ? null
						: sym.getName();
				AbstractProgramLoader.markAsFunction(program, name, local);
				FunctionManager fm = program.getFunctionManager();
				Function outer = fm.getFunctionAt(entry);
				outer.setBody(new AddressSet(entry, local.subtract(1)));
				outer.setThunkedFunction(fm.getFunctionAt(local));
			}
			catch (Exception e) {
				log.appendMsg("Cannot split the GP prologue at " + entry + ": " + e.getMessage());
			}
		}
	}
}
