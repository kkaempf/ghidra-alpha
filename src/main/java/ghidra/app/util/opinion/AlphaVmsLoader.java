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
import java.math.BigInteger;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for OpenVMS Alpha images: executables, shareable images and
 * executive images.
 *
 * <p>Memory comes from the image section descriptors, with the protection
 * the image activator gives each range once it has applied the fixups, so
 * linkage sections are read-only and the decompiler folds loads from them.
 *
 * <p>Procedures are found through their procedure descriptors: the transfer
 * addresses, the global symbol table, and a scan of the data sections. On
 * entry R27 holds the address of the procedure's descriptor, which is how
 * the code reaches its linkage section, so R27 is set to it in the program
 * context at each entry.
 */
public class AlphaVmsLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "OpenVMS Alpha image";

	static final int EIHD_LENGTH = 104;
	static final int BLOCK = 512;

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		Header h = Header.parse(new BinaryReader(provider, true));
		if (h == null) {
			return specs;
		}
		for (LanguageDescription ld : getLanguageService().getLanguageDescriptions(false)) {
			String id = ld.getLanguageID().getIdAsString();
			if (!ld.getProcessor().toString().equals("Alpha") || !id.endsWith(":vms")) {
				continue;
			}
			for (CompilerSpecDescription cs : ld.getCompatibleCompilerSpecDescriptions()) {
				specs.add(new LoadSpec(this, h.linkedBase,
					new LanguageCompilerSpecPair(ld.getLanguageID(), cs.getCompilerSpecID()),
					id.startsWith("21264:")));
			}
		}
		return specs;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		BinaryReader r = new BinaryReader(settings.provider(), true);
		Header h = Header.parse(r);
		if (h == null) {
			throw new IOException("Not an OpenVMS Alpha image");
		}
		new Image(program, r, h, settings.log(), settings.monitor()).load();
	}

	/** An image section descriptor (EISD). */
	record Eisd(long va, long size, int flags, int vbn, int type, String gblName) {
		static final int GBL = 0x1, DZRO = 0x4, WRT = 0x8, FIXUPVEC = 0x40, EXE = 0x800;
		static final int TYPE_USRSTACK = 253;

		boolean isGlobal() {
			return (flags & GBL) != 0;
		}
	}

	/** The image header (EIHD) and its section descriptors. */
	static final class Header {
		int imgtype, subtype, lnkflags, sysver, symvectSize;
		long activoff, symdbgoff, iafva, symvva;
		final List<Eisd> eisds = new ArrayList<>();
		/** The lowest section address, which fixup offsets are relative to. */
		long linkedBase = -1;
		Eisd fixups;

		/** The header, or null if this is not an OpenVMS Alpha image. */
		static Header parse(BinaryReader r) throws IOException {
			long len = r.length();
			if (len < BLOCK || r.readInt(0) != 3 || r.readInt(4) != 0) {
				return null;
			}
			long size = r.readUnsignedInt(8);
			long isdoff = r.readUnsignedInt(12);
			long hdrEnd = BLOCK * Math.max(1, r.readUnsignedInt(76));
			if (size < EIHD_LENGTH || size > hdrEnd || hdrEnd > len || isdoff < EIHD_LENGTH ||
				isdoff >= hdrEnd) {
				return null;
			}
			Header h = new Header();
			h.activoff = r.readUnsignedInt(16);
			h.symdbgoff = r.readUnsignedInt(20);
			h.iafva = r.readLong(32);
			h.symvva = r.readLong(40);
			h.imgtype = r.readInt(52);
			h.subtype = r.readInt(56);
			h.lnkflags = r.readInt(80);
			h.sysver = r.readInt(88);
			h.symvectSize = r.readInt(96);

			long o = isdoff;
			while (o + 4 <= hdrEnd && h.eisds.size() < 1024) {
				long eisdsize = r.readUnsignedInt(o + 8);
				if (eisdsize == 0) {
					break;
				}
				if (eisdsize == 0xffffffffL) {
					o = (o / BLOCK + 1) * BLOCK;
					continue;
				}
				if (r.readInt(o) != 1 || eisdsize < 36 || o + eisdsize > hdrEnd) {
					return null;
				}
				int flags = r.readInt(o + 24);
				String gbl = null;
				if ((flags & Eisd.GBL) != 0 && eisdsize >= 41) {
					gbl = r.readAsciiString(o + 41, Math.min(r.readUnsignedByte(o + 40),
						(int) eisdsize - 41));
				}
				Eisd e = new Eisd(r.readLong(o + 16), r.readUnsignedInt(o + 12), flags,
					r.readInt(o + 28), r.readUnsignedByte(o + 34), gbl);
				h.eisds.add(e);
				if (!e.isGlobal() && e.type() != Eisd.TYPE_USRSTACK) {
					h.linkedBase = h.linkedBase == -1 ? e.va()
							: Math.min(h.linkedBase, e.va());
				}
				if ((flags & Eisd.FIXUPVEC) != 0 && e.vbn() != 0) {
					h.fixups = e;
				}
				o += eisdsize;
			}
			return h.linkedBase == -1 ? null : h;
		}

		/** File offset of the global symbol table, or -1. */
		long gstOffset(BinaryReader r) throws IOException {
			if (symdbgoff == 0) {
				return -1;
			}
			long vbn = r.readUnsignedInt(symdbgoff + 16);
			return vbn == 0 ? -1 : (vbn - 1) * BLOCK;
		}
	}

	/** A global symbol: SYMG in shareable images, SYMV in executive images. */
	record GlobalSymbol(boolean symv, int flags, long value, long entry, long pd, int vector,
			String name) {
		static final int DEF = 0x2, REL = 0x8, NORM = 0x40;

		boolean isProcedure() {
			return (flags & NORM) != 0;
		}
	}

	/**
	 * The global symbol table, stored as RMS variable-length records: a
	 * length word, then the record, padded to an even length.
	 */
	static List<GlobalSymbol> readGst(BinaryReader r, Header h) throws IOException {
		List<GlobalSymbol> out = new ArrayList<>();
		long o = h.gstOffset(r);
		if (o < 0) {
			return out;
		}
		long len = r.length();
		while (o + 6 <= len) {
			int ln = r.readUnsignedShort(o);
			if (ln == 0xffff) {
				o = (o / BLOCK + 1) * BLOCK;
				continue;
			}
			int rectyp = r.readUnsignedShort(o + 2);
			if (ln == 0 || rectyp == 9) {
				break;
			}
			long rec = o + 2;
			if (rectyp == 10) {
				long end = rec + Math.min(ln, r.readUnsignedShort(rec + 2));
				for (long e = rec + 8; e + 4 <= end;) {
					int type = r.readUnsignedShort(e);
					int sz = r.readUnsignedShort(e + 2);
					if (sz == 0) {
						break;
					}
					int flags = r.readUnsignedShort(e + 6);
					if (type == 8 && sz >= 37) {
						out.add(new GlobalSymbol(false, flags, r.readLong(e + 8),
							r.readLong(e + 16), r.readLong(e + 24), 0,
							r.readAsciiString(e + 37, r.readUnsignedByte(e + 36))));
					}
					else if (type == 6 && sz >= 25) {
						out.add(new GlobalSymbol(true, flags, r.readLong(e + 8), 0, 0,
							r.readInt(e + 20),
							r.readAsciiString(e + 25, r.readUnsignedByte(e + 24))));
					}
					e += sz;
				}
			}
			o = rec + ln + (ln & 1);
		}
		return out;
	}

	private static class Image {
		// Procedure descriptor kinds.
		static final int PDSC_KIND_NULL = 8, PDSC_KIND_FP_STACK = 9, PDSC_KIND_FP_REGISTER = 10;

		// Memory protection codes that allow no write access.
		static final Set<Integer> READ_ONLY = Set.of(0, 3, 7, 11, 15);

		final Program program;
		final BinaryReader r;
		final Header h;
		final MessageLog log;
		final TaskMonitor monitor;
		final AddressSpace space;
		final Memory memory;
		final SymbolTable symbols;
		final Register pvReg;
		/** Where the image is loaded minus where it was linked. */
		long delta;
		/** Procedure descriptors found, by address, with their entries. */
		final Map<Long, Long> pds = new TreeMap<>(Long::compareUnsigned);
		DataType pdscType;

		Image(Program program, BinaryReader r, Header h, MessageLog log, TaskMonitor monitor) {
			this.program = program;
			this.r = r;
			this.h = h;
			this.log = log;
			this.monitor = monitor;
			this.space = program.getAddressFactory().getDefaultAddressSpace();
			this.memory = program.getMemory();
			this.symbols = program.getSymbolTable();
			this.pvReg = program.getLanguage()
					.getRegister(program.getAddressFactory().getRegisterSpace(), 27 * 8, 8);
		}

		Address addr(long offset) {
			return space.getAddress(offset);
		}

		/** The address of a location given relative to the image base. */
		long rva(long offset) {
			return h.linkedBase + delta + offset;
		}

		void load() throws IOException, CancelledException {
			createBlocks();
			if (h.fixups != null) {
				Eiaf eiaf = new Eiaf((h.fixups.vbn() - 1L) * BLOCK, h.fixups.size());
				changeProtection(eiaf);
			}
			labelGlobals(readGst(r, h));
			transferAddresses();
			scanForPds();
		}

		void createBlocks() throws IOException, CancelledException {
			FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, r.getByteProvider(),
				monitor);
			long len = r.length();
			int n = 0;
			for (Eisd e : h.eisds) {
				if (e.isGlobal() || e.type() == Eisd.TYPE_USRSTACK || e.size() == 0) {
					continue;
				}
				boolean exec = (e.flags() & Eisd.EXE) != 0;
				boolean write = (e.flags() & Eisd.WRT) != 0;
				String name = ((e.flags() & Eisd.FIXUPVEC) != 0 ? "fixups"
						: exec ? "code" : e.vbn() == 0 ? "zero" : "data") + "_" + n++;
				Address start = addr(e.va() + delta);
				long fileOff = (e.vbn() - 1L) * BLOCK;
				long initialized = e.vbn() == 0 ? 0 : Math.max(0, Math.min(e.size(), len - fileOff));
				if (e.vbn() != 0 && initialized < e.size()) {
					log.appendMsg(name + " extends past the end of the file");
				}
				try {
					if (initialized > 0) {
						MemoryBlockUtils.createInitializedBlock(program, false, name, start,
							fileBytes, fileOff, initialized, null, NAME, true, write, exec, log);
					}
					if (initialized < e.size()) {
						MemoryBlockUtils.createUninitializedBlock(program, false,
							initialized == 0 ? name : name + ".rest", start.add(initialized),
							e.size() - initialized, null, NAME, true, write, exec, log);
					}
				}
				catch (Exception x) {
					log.appendMsg("Skipping section " + name + ": " + x.getMessage());
				}
			}
		}

		/** The image activator fixup section (EIAF). */
		final class Eiaf {
			final long base;
			final long size;

			Eiaf(long base, long size) {
				this.base = base;
				this.size = Math.min(size, r.length() - base);
			}

			long field(int off) throws IOException {
				return size < off + 4 ? 0 : r.readUnsignedInt(base + off);
			}

			boolean contains(long off, long n) {
				return off > 0 && off + n <= size;
			}
		}

		/**
		 * The image activator changes the protection of ranges once it has
		 * applied the fixups, which leaves linkage sections read-only.
		 */
		void changeProtection(Eiaf eiaf) throws IOException {
			long off = eiaf.field(56);
			if (!eiaf.contains(off, 4)) {
				return;
			}
			long count = r.readUnsignedInt(eiaf.base + off);
			off += 4;
			for (long i = 0; i < count && eiaf.contains(off, 16); i++, off += 16) {
				long start = rva(r.readLong(eiaf.base + off));
				long size = r.readUnsignedInt(eiaf.base + off + 8);
				int prot = r.readInt(eiaf.base + off + 12);
				if (size > 0) {
					setWrite(addr(start), addr(start + size - 1), !READ_ONLY.contains(prot));
				}
			}
		}

		void setWrite(Address start, Address end, boolean write) {
			try {
				MemoryBlock b = memory.getBlock(start);
				if (b != null && b.getStart().compareTo(start) < 0) {
					memory.split(b, start);
				}
				b = memory.getBlock(end);
				if (b != null && b.getEnd().compareTo(end) > 0) {
					memory.split(b, end.add(1));
				}
				for (MemoryBlock blk : memory.getBlocks()) {
					if (blk.getStart().compareTo(start) >= 0 && blk.getEnd().compareTo(end) <= 0) {
						blk.setWrite(write);
					}
				}
			}
			catch (Exception e) {
				log.appendMsg("Cannot change the protection of " + start + ": " + e.getMessage());
			}
		}

		/** The entry of the procedure descriptor at pd, or null if there is none. */
		Long pdEntry(long pd) {
			if ((pd & 7) != 0) {
				return null;
			}
			try {
				Address a = addr(pd);
				int kind = memory.getShort(a) & 0xf;
				if (kind < PDSC_KIND_NULL || kind > PDSC_KIND_FP_REGISTER) {
					return null;
				}
				long entry = memory.getLong(a.add(8));
				MemoryBlock code = memory.getBlock(addr(entry));
				if ((entry & 3) != 0 || code == null || !code.isExecute() ||
					!code.isInitialized()) {
					return null;
				}
				if (kind != PDSC_KIND_NULL) {
					int frame = memory.getInt(a.add(16));
					if ((frame & 0xf) != 0 || frame < 0 || frame > 0x100000) {
						return null;
					}
				}
				return entry;
			}
			catch (Exception e) {
				return null;
			}
		}

		/**
		 * Mark the procedure whose descriptor is at pd, with R27 holding the
		 * descriptor's address on entry. Returns its entry, or null.
		 */
		Address procedure(long pd, String name) {
			Long entry = pds.get(pd);
			if (entry == null) {
				entry = pdEntry(pd);
				if (entry == null) {
					return null;
				}
				pds.put(pd, entry);
				Address pdAddr = addr(pd);
				try {
					DataUtilities.createData(program, pdAddr, pdscType(), -1,
						ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
				}
				catch (Exception e) {
					// leave it undefined
				}
				Address e = addr(entry);
				AbstractProgramLoader.markAsFunction(program, null, e);
				try {
					program.getProgramContext().setValue(pvReg, e, e,
						new BigInteger(Long.toUnsignedString(pd)));
				}
				catch (Exception x) {
					log.appendMsg("Cannot set R27 at " + e + ": " + x.getMessage());
				}
			}
			if (name != null) {
				label(pd, "PD_" + name);
				label(entry, name);
			}
			return addr(entry);
		}

		/** The fixed part of a procedure descriptor. */
		DataType pdscType() {
			if (pdscType == null) {
				StructureDataType s = new StructureDataType("PDSC", 0);
				s.add(WordDataType.dataType, "flags", "KIND in bits 0-3");
				s.add(WordDataType.dataType, "rsa_offset",
					"save_fp and save_ra bytes in a register frame");
				s.add(ByteDataType.dataType, "reserved", null);
				s.add(ByteDataType.dataType, "func_return", "FUNC_RETURN in bits 0-3");
				s.add(WordDataType.dataType, "signature_offset", null);
				s.add(PointerDataType.dataType, 8, "entry", null);
				pdscType = program.getDataTypeManager().addDataType(s, null);
			}
			return pdscType;
		}

		void label(long offset, String name) {
			Address a = addr(offset);
			if (name == null || name.isEmpty() || !memory.contains(a)) {
				return;
			}
			try {
				symbols.createLabel(a, name, SourceType.IMPORTED);
			}
			catch (Exception e) {
				log.appendMsg("Cannot label " + a + " " + name + ": " + e.getMessage());
			}
		}

		/** Names of the image's own universal symbols. */
		void labelGlobals(List<GlobalSymbol> gst) {
			for (GlobalSymbol s : gst) {
				if ((s.flags() & GlobalSymbol.DEF) == 0) {
					continue;
				}
				long value = s.symv() ? s.value() : s.pd();
				if (s.isProcedure()) {
					if (procedure(value + delta, s.name()) == null && !s.symv()) {
						// Not a descriptor we recognize; name the code.
						label(s.entry() + delta, s.name());
					}
				}
				else if ((s.flags() & GlobalSymbol.REL) != 0) {
					label(value + delta, s.name());
				}
			}
			if (h.symvva != 0 && h.symvectSize > 0) {
				label(h.symvva + delta, "SYMBOL_VECTOR");
			}
		}

		/** The activation header's transfer addresses are procedure descriptors. */
		void transferAddresses() throws IOException {
			if (h.activoff == 0) {
				return;
			}
			int n = 0;
			for (int i = 0; i < 4; i++) {
				long pd = r.readLong(h.activoff + 8 + 8L * i);
				if (pd == 0) {
					break;
				}
				Address entry = procedure(pd + delta, null);
				if (entry == null) {
					continue;
				}
				symbols.addExternalEntryPoint(entry);
				if (symbols.getPrimarySymbol(entry) == null ||
					symbols.getPrimarySymbol(entry).getSource() == SourceType.DEFAULT) {
					label(entry.getOffset(), n == 0 ? "entry" : "entry_" + n);
				}
				n++;
			}
		}

		/** Procedure descriptors anywhere in the initialized data. */
		void scanForPds() throws CancelledException {
			for (MemoryBlock b : memory.getBlocks()) {
				if (b.isExecute() || !b.isInitialized()) {
					continue;
				}
				long start = (b.getStart().getOffset() + 7) & ~7L;
				for (long a = start; Long.compareUnsigned(a + 16, b.getEnd().getOffset() + 1) <= 0;
						a += 8) {
					monitor.checkCancelled();
					if (pds.containsKey(a) || pdEntry(a) != null && procedure(a, null) != null) {
						a += 8;
					}
				}
			}
		}
	}
}
