all: data/languages/alpha.sla

data/languages/alpha.sla: data/languages/alpha.slaspec 
	/abuild/projects/Ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh_dbg $^
	sleigh $^ $@

test:
	make -C tests

clean:
	rm -rf data/languages/alpha.sla
	make -C tests clean
