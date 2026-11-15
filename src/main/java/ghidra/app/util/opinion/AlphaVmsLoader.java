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

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.AccessMode;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.*;
import ghidra.app.util.importer.LibrarySearchPathManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.*;
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
 *
 * <p>Each import gets an external function or data location, found by its
 * symbol vector offset in the global symbol table of the shareable image
 * that exports it, which is looked for beside the image and in the library
 * search paths. Slots in SYS$BASE_IMAGE are named from the executive images
 * beside it, which fill them. Each fixup puts the address of the import's
 * thunk or data cell in its linkage pair or address cell.
 *
 * <p>Images with relocations, such as shareable and executive images linked
 * at 0, can be loaded at a chosen base. Executive images default to the
 * start of system space, and others to the lowest address a user image is
 * normally linked at.
 */
public class AlphaVmsLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "OpenVMS Alpha image";
	public static final String OPTION_BASE = "Image base";

	static final long USER_BASE = 0x10000L;
	static final long SYSTEM_BASE = 0xffffffff80000000L;

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
				specs.add(new LoadSpec(this, h.defaultBase(),
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
		Image image = new Image(program, r, h, settings.provider().getFile(), settings.log(),
			settings.monitor());
		if (h.relocatable) {
			image.delta = parseBase(settings.options(), h) - h.linkedBase;
		}
		image.load();
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> options = super.getDefaultOptions(provider, loadSpec, domainObject,
			loadIntoProgram, mirrorFsLayout);
		try {
			Header h = Header.parse(new BinaryReader(provider, true));
			if (h != null && h.relocatable && !loadIntoProgram) {
				options.add(new Option(OPTION_BASE, "0x" + Long.toHexString(h.defaultBase())));
			}
		}
		catch (IOException e) {
			// no base option
		}
		return options;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		for (Option o : options) {
			if (o.getName().equals(OPTION_BASE)) {
				try {
					long base = parseHex(String.valueOf(o.getValue()));
					if ((base & 0xffff) != 0) {
						return OPTION_BASE + " must be a multiple of 0x10000";
					}
				}
				catch (NumberFormatException e) {
					return OPTION_BASE + " must be a hexadecimal address";
				}
				break;
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	static long parseBase(List<Option> options, Header h) {
		for (Option o : options == null ? List.<Option> of() : options) {
			if (o.getName().equals(OPTION_BASE)) {
				return parseHex(String.valueOf(o.getValue()));
			}
		}
		return h.defaultBase();
	}

	static long parseHex(String text) {
		text = text.trim();
		if (text.startsWith("0x") || text.startsWith("0X")) {
			text = text.substring(2);
		}
		return Long.parseUnsignedLong(text, 16);
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
		/** Whether the image activator relocates the image. */
		boolean relocatable;

		boolean isExecutive() {
			return imgtype == 2 && subtype == 0 && sysver != 0;
		}

		long defaultBase() {
			if (!relocatable || linkedBase != 0) {
				return linkedBase;
			}
			return isExecutive() ? SYSTEM_BASE : USER_BASE;
		}

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
			if (h.linkedBase == -1) {
				return null;
			}
			if (h.fixups != null) {
				long eiaf = (h.fixups.vbn() - 1L) * BLOCK;
				h.relocatable = eiaf + 40 <= len &&
					(r.readInt(eiaf + 32) != 0 || r.readInt(eiaf + 36) != 0);
			}
			return h;
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

		// Relocation types recorded for the fixups.
		static final int FIX_QREL = 1, FIX_LREL = 2, FIX_QDOTADR = 3, FIX_LDOTADR = 4,
				FIX_CODEADR = 5, FIX_LP = 6;

		static final Set<String> NO_RETURN = Set.of("SYS$EXIT", "LIB$STOP", "DECC$EXIT",
			"DECC$_EXIT", "DECC$ABORT", "DECC$LONGJMP", "DECC$_LONGJMP", "DECC$SIGLONGJMP",
			"DECC$__UTC_EXIT", "CMA$THREAD_EXIT");

		final Program program;
		final BinaryReader r;
		final Header h;
		final File file;
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

		Image(Program program, BinaryReader r, Header h, File file, MessageLog log,
				TaskMonitor monitor) {
			this.program = program;
			this.r = r;
			this.h = h;
			this.file = file;
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
			Eiaf eiaf = h.fixups == null ? null
					: new Eiaf((h.fixups.vbn() - 1L) * BLOCK, h.fixups.size());
			if (eiaf != null) {
				relocate(eiaf, eiaf.field(32), 8, FIX_QREL);
				relocate(eiaf, eiaf.field(36), 4, FIX_LREL);
				changeProtection(eiaf);
			}
			labelGlobals(readGst(r, h));
			transferAddresses();
			// Before the imports overwrite their linkage pairs with thunk
			// addresses, which can look like descriptors.
			scanForPds();
			if (eiaf != null) {
				imports(eiaf);
			}
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
		 * Relocation records are a bit count and a base offset, then a bitmap
		 * with a bit for each quadword or longword from the base that holds
		 * an address relative to the image base.
		 */
		void relocate(Eiaf eiaf, long off, int stride, int type)
				throws IOException, CancelledException {
			while (eiaf.contains(off, 8)) {
				long count = r.readUnsignedInt(eiaf.base + off);
				long base = r.readUnsignedInt(eiaf.base + off + 4);
				if (count == 0) {
					return;
				}
				off += 8;
				for (long word = 0; word * 32 < count && eiaf.contains(off, 4); word++, off += 4) {
					monitor.checkCancelled();
					int bits = r.readInt(eiaf.base + off);
					for (int k = 0; k < 32; k++) {
						if ((bits & (1 << k)) != 0) {
							relocateAt(addr(rva(base + (word * 32 + k) * stride)), stride, type);
						}
					}
				}
			}
		}

		void relocateAt(Address at, int stride, int type) {
			try {
				long old = stride == 8 ? memory.getLong(at) : memory.getInt(at);
				if (delta != 0) {
					if (stride == 8) {
						memory.setLong(at, old + delta);
					}
					else {
						memory.setInt(at, (int) (old + delta));
					}
				}
				program.getRelocationTable()
						.add(at, Status.APPLIED, type, new long[] { old }, stride, null);
			}
			catch (Exception e) {
				log.appendMsg("Cannot relocate " + at + ": " + e.getMessage());
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

		/** A reference from the image to a symbol another image exports. */
		record Fixup(int type, int image, long at, long svo) {
		}

		/** An imported symbol and where its thunk or cell is. */
		record Import(ExternalLocation loc, Address slot) {
		}

		/**
		 * Linkage pairs, code addresses and .address cells that refer to
		 * other images. Each fixup list is a run of groups: a count, the
		 * index of the shareable image, then the locations.
		 */
		void imports(Eiaf eiaf) throws IOException, CancelledException {
			List<String> shl = new ArrayList<>();
			long shlOff = eiaf.field(60);
			long shlCount = eiaf.field(64);
			for (long i = 0; i < shlCount && eiaf.contains(shlOff + 64 * i, 64); i++) {
				long o = eiaf.base + shlOff + 64 * i;
				shl.add(r.readAsciiString(o + 25, Math.min(39, r.readUnsignedByte(o + 24))));
			}
			if (shl.isEmpty()) {
				return;
			}

			List<Fixup> fixups = new ArrayList<>();
			referenceFixups(eiaf, eiaf.field(52), 4, FIX_LP, fixups);
			// Linkage pairs whose calls carry a procedure signature block,
			// as LIBRTL's calls into SYS$PUBLIC_VECTORS do. Each entry is
			// the linkage pair and the address of its signature block.
			referenceFixups(eiaf, eiaf.field(80), 8, FIX_LP, fixups);
			referenceFixups(eiaf, eiaf.field(48), 4, FIX_CODEADR, fixups);
			addressFixups(eiaf, eiaf.field(40), FIX_QDOTADR, fixups);
			addressFixups(eiaf, eiaf.field(44), FIX_LDOTADR, fixups);
			fixups.removeIf(f -> f.image() >= shl.size() || !memory.contains(addr(f.at())));
			if (fixups.isEmpty()) {
				return;
			}

			Map<String, Map<Long, GlobalSymbol>> exports = new HashMap<>();
			Map<List<Long>, Import> imports = new HashMap<>();
			Address slots = createExternalBlock(
				fixups.stream().map(f -> List.of((long) f.image(), f.svo())).distinct().count());
			if (slots == null) {
				return;
			}
			ExternalManager ext = program.getExternalManager();
			ReferenceManager refs = program.getReferenceManager();
			int n = 0;
			for (Fixup f : fixups) {
				monitor.checkCancelled();
				List<Long> key = List.of((long) f.image(), f.svo());
				Import imp = imports.get(key);
				if (imp == null) {
					String lib = shl.get(f.image());
					Map<Long, GlobalSymbol> syms = exports.computeIfAbsent(lib, this::exports);
					GlobalSymbol sym = syms.get(f.svo());
					String name = sym != null ? sym.name()
							: String.format("%s_%X", lib.replaceFirst("^SYS\\$", ""), f.svo());
					boolean proc = sym != null ? sym.isProcedure() : f.type() == FIX_LP ||
						f.type() == FIX_CODEADR;
					imp = newImport(ext, lib, name, proc, slots.add(8L * n++));
					if (imp == null) {
						continue;
					}
					imports.put(key, imp);
				}
				write(f, imp, refs);
			}
		}

		void referenceFixups(Eiaf eiaf, long off, int stride, int type, List<Fixup> out)
				throws IOException {
			while (eiaf.contains(off, 8)) {
				long count = r.readUnsignedInt(eiaf.base + off);
				int image = r.readInt(eiaf.base + off + 4);
				if (count == 0) {
					return;
				}
				off += 8;
				for (long j = 0; j < count && eiaf.contains(off, stride); j++, off += stride) {
					long at = rva(r.readUnsignedInt(eiaf.base + off));
					// The location holds the symbol vector offset of the target.
					try {
						out.add(new Fixup(type, image, at, memory.getLong(addr(at))));
					}
					catch (Exception e) {
						log.appendMsg("Cannot read the fixup at " + addr(at));
					}
				}
			}
		}

		void addressFixups(Eiaf eiaf, long off, int type, List<Fixup> out) throws IOException {
			while (eiaf.contains(off, 8)) {
				long count = r.readUnsignedInt(eiaf.base + off);
				int image = r.readInt(eiaf.base + off + 4);
				if (count == 0) {
					return;
				}
				off += 8;
				for (long j = 0; j < count && eiaf.contains(off, 8); j++, off += 8) {
					out.add(new Fixup(type, image, rva(r.readUnsignedInt(eiaf.base + off)),
						r.readUnsignedInt(eiaf.base + off + 4)));
				}
			}
		}

		Import newImport(ExternalManager ext, String lib, String name, boolean proc,
				Address slot) {
			try {
				ExternalLocation loc;
				if (proc) {
					loc = ext.addExtFunction(lib, name, null, SourceType.IMPORTED);
					if (NO_RETURN.contains(name)) {
						loc.getFunction().setNoReturn(true);
					}
					Function f = program.getFunctionManager()
							.createFunction(name, slot, new AddressSet(slot), SourceType.IMPORTED);
					f.setThunkedFunction(loc.getFunction());
				}
				else {
					loc = ext.addExtLocation(lib, name, null, SourceType.IMPORTED);
					symbols.createLabel(slot, name, SourceType.IMPORTED);
				}
				return new Import(loc, slot);
			}
			catch (Exception e) {
				log.appendMsg("Cannot create import " + lib + " " + name + ": " + e.getMessage());
				return null;
			}
		}

		/**
		 * Point a fixup at its import's slot. Calls through read-only cells
		 * fold to the thunk. Writable cells, as in executive images, do not,
		 * so they get an external reference instead. The decompiler fails
		 * on a function that reaches one external through different cells,
		 * so the read-only cells do not get one.
		 */
		void write(Fixup f, Import imp, ReferenceManager refs) {
			Address at = addr(f.at());
			long slot = imp.slot().getOffset();
			try {
				int len = 8;
				if (f.type() == FIX_LDOTADR) {
					if ((int) slot != slot) {
						log.appendMsg("Import slot " + imp.slot() + " does not fit at " + at);
					}
					memory.setInt(at, (int) slot);
					len = 4;
				}
				else {
					memory.setLong(at, slot);
					pointer(at);
					if (f.type() == FIX_LP) {
						memory.setLong(at.add(8), slot);
						pointer(at.add(8));
						len = 16;
					}
				}
				program.getRelocationTable()
						.add(at, Status.APPLIED, f.type(), new long[] { f.image(), f.svo() }, len,
							imp.loc().getLabel());
				refs.removeAllReferencesFrom(at);
				boolean call = f.type() == FIX_LP || f.type() == FIX_CODEADR;
				MemoryBlock block = memory.getBlock(at);
				if (call && block != null && !block.isWrite()) {
					refs.addMemoryReference(at, imp.slot(), RefType.DATA, SourceType.IMPORTED, 0);
				}
				else {
					refs.addExternalReference(at, 0, imp.loc(), SourceType.IMPORTED,
						call ? RefType.COMPUTED_CALL : RefType.DATA);
				}
			}
			catch (Exception e) {
				log.appendMsg("Cannot apply the fixup at " + at + ": " + e.getMessage());
			}
		}

		void pointer(Address at) {
			try {
				DataUtilities.createData(program, at, PointerDataType.dataType, 8,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			catch (Exception e) {
				// leave it undefined
			}
		}

		Address createExternalBlock(long count) {
			long end = 0;
			for (MemoryBlock b : memory.getBlocks()) {
				end = Math.max(end, b.getEnd().getOffset() + 1);
			}
			Address start = addr((end + 0xffff) & ~0xffffL);
			MemoryBlock b = MemoryBlockUtils.createUninitializedBlock(program, false,
				MemoryBlock.EXTERNAL_BLOCK_NAME, start, 8L * count,
				"Thunks for imported procedures and cells for imported data", NAME, true, false,
				false, log);
			if (b == null) {
				return null;
			}
			b.setArtificial(true);
			return start;
		}

		/** What a shareable image exports, by symbol vector offset. */
		Map<Long, GlobalSymbol> exports(String lib) {
			Map<Long, GlobalSymbol> out = new HashMap<>();
			File f = findImage(lib);
			if (f == null) {
				log.appendMsg("Cannot find " + lib + ".EXE; its imports are named by offset");
				return out;
			}
			for (GlobalSymbol s : globals(f)) {
				if (!s.symv() && (s.flags() & GlobalSymbol.DEF) != 0) {
					out.putIfAbsent(s.value(), s);
				}
			}
			// The executive images fill most of the base image's symbol
			// vector, which its own symbol table leaves out.
			if (lib.equalsIgnoreCase("SYS$BASE_IMAGE")) {
				File[] dir = f.getParentFile().listFiles();
				for (File exec : dir == null ? new File[0] : dir) {
					if (exec.isFile() && imageName(exec.getName()).endsWith(".EXE")) {
						for (GlobalSymbol s : globals(exec)) {
							if (s.symv()) {
								out.putIfAbsent(Integer.toUnsignedLong(s.vector()), s);
							}
						}
					}
				}
			}
			return out;
		}

		static String imageName(String fileName) {
			// ODS-2 file names may carry a version.
			return fileName.replaceFirst(";\\d*$", "").toUpperCase(Locale.ROOT);
		}

		List<GlobalSymbol> globals(File f) {
			try (ByteProvider p = new FileByteProvider(f, null, AccessMode.READ)) {
				BinaryReader lr = new BinaryReader(p, true);
				Header lh = Header.parse(lr);
				return lh == null ? List.of() : readGst(lr, lh);
			}
			catch (IOException e) {
				log.appendMsg("Cannot read " + f + ": " + e.getMessage());
				return List.of();
			}
		}

		/** The shareable image beside this one or in a library search path. */
		File findImage(String lib) {
			List<File> dirs = new ArrayList<>();
			File own = file == null ? null : file.getParentFile();
			if (own != null) {
				dirs.add(own);
			}
			for (String path : LibrarySearchPathManager.getLibraryPaths()) {
				File d = new File(path);
				if (d.isAbsolute()) {
					dirs.add(d);
				}
			}
			String want = lib.toUpperCase(Locale.ROOT) + ".EXE";
			for (File d : dirs) {
				File[] files = d.listFiles();
				for (File f : files == null ? new File[0] : files) {
					if (f.isFile() && imageName(f.getName()).equals(want)) {
						return f;
					}
				}
			}
			return null;
		}

		/**
		 * Procedure descriptors anywhere in the initialized data. The tail of
		 * one linkage pair and the entry of the next can look like a
		 * descriptor for the same procedure, so when several point at one
		 * entry, take the one a linkage pair (entry, descriptor) refers to.
		 */
		void scanForPds() throws CancelledException {
			Map<Long, Long> found = new LinkedHashMap<>();
			Set<Long> linked = new HashSet<>();
			for (int pass = 0; pass < 2; pass++) {
				for (MemoryBlock b : memory.getBlocks()) {
					if (b.isExecute() || !b.isInitialized()) {
						continue;
					}
					long end = b.getEnd().getOffset() + 1;
					for (long a = (b.getStart().getOffset() + 7) & ~7L;
							Long.compareUnsigned(a + 16, end) <= 0; a += 8) {
						monitor.checkCancelled();
						if (pass == 0) {
							Long entry = pdEntry(a);
							if (entry != null) {
								found.put(a, entry);
							}
							continue;
						}
						try {
							long pd = memory.getLong(addr(a + 8));
							Long entry = found.get(pd);
							if (entry != null && entry == memory.getLong(addr(a))) {
								linked.add(pd);
							}
						}
						catch (Exception e) {
							// not a linkage pair
						}
					}
				}
			}

			Set<Long> known = new HashSet<>(pds.values());
			Map<Long, List<Long>> byEntry = new LinkedHashMap<>();
			for (Map.Entry<Long, Long> e : found.entrySet()) {
				if (!known.contains(e.getValue())) {
					byEntry.computeIfAbsent(e.getValue(), k -> new ArrayList<>()).add(e.getKey());
				}
			}
			for (Map.Entry<Long, List<Long>> e : byEntry.entrySet()) {
				List<Long> candidates = e.getValue();
				if (candidates.size() > 1) {
					candidates.removeIf(pd -> !linked.contains(pd));
				}
				if (candidates.size() == 1) {
					procedure(candidates.get(0), null);
				}
				else {
					AbstractProgramLoader.markAsFunction(program, null, addr(e.getKey()));
				}
			}
		}
	}
}
