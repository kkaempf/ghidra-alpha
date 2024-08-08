all: data/languages/21064.sla data/languages/21164.sla data/languages/21264.sla test

data/languages/21064.sla: data/languages/21064.slaspec data/languages/alpha.sinc

data/languages/21164.sla: data/languages/21164.slaspec data/languages/alpha.sinc

data/languages/21264.sla: data/languages/21264.slaspec data/languages/alpha.sinc

%.sla: %.slaspec
	/abuild/projects/Ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh_dbg $<
	sleigh -u $< $@

test:
	make -C tests

clean:
	rm -rf data/languages/alpha.sla
	make -C tests clean
