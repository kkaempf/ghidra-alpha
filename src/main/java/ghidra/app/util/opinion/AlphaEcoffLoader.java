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
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Tru64 UNIX (Digital UNIX, DEC OSF/1) Alpha ECOFF executables and
 * shared libraries.
 *
 * <p>Function starts come from the ECOFF symbol table when present, from
 * .dynsym, and from the code range descriptors in .pdata.
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

		// .dynsym section indices and symbol types.
		static final int SHN_UNDEF = 0, SHN_TEXT = 0xff01;
		static final int STT_FUNC = 2;

		final Program program;
		final BinaryReader r;
		final MessageLog log;
		final TaskMonitor monitor;
		final AddressSpace space;
		final Memory memory;
		final SymbolTable symbols;
		final Map<String, Section> sections = new LinkedHashMap<>();

		Image(Program program, ByteProvider provider, MessageLog log, TaskMonitor monitor) {
			this.program = program;
			this.r = new BinaryReader(provider, true);
			this.log = log;
			this.monitor = monitor;
			this.space = program.getAddressFactory().getDefaultAddressSpace();
			this.memory = program.getMemory();
			this.symbols = program.getSymbolTable();
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

		/** .dynsym names. */
		void loadDynamic() throws IOException {
			Section dynsym = sections.get(".dynsym");
			Section dynstr = sections.get(".dynstr");
			if (dynsym == null || dynstr == null) {
				return;
			}
			for (long o = dynsym.scnptr(); o + 24 <= dynsym.scnptr() + dynsym.size(); o += 24) {
				String name = r.readAsciiString(dynstr.scnptr() + r.readUnsignedInt(o));
				int shndx = r.readUnsignedShort(o + 22);
				if (!name.isEmpty() && !name.startsWith(".") && shndx != SHN_UNDEF) {
					label(r.readLong(o + 8), name,
						shndx == SHN_TEXT && (r.readUnsignedByte(o + 20) & 0xf) == STT_FUNC);
				}
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
				}
			}
		}

	}
}
