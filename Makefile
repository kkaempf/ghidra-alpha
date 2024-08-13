all: nt unix vms test

vms: data/languages/21064VMS.sla data/languages/21164VMS.sla data/languages/21264VMS.sla data/languages/21364VMS.sla
unix: data/languages/21064UNIX.sla data/languages/21164UNIX.sla data/languages/21264UNIX.sla data/languages/21364UNIX.sla
nt: data/languages/21064NT.sla data/languages/21164NT.sla data/languages/21264NT.sla data/languages/21364NT.sla

data/languages/21064VMS.sla: data/languages/21064VMS.slaspec data/languages/alpha.sinc

data/languages/21064UNIX.sla: data/languages/21064UNIX.slaspec data/languages/alpha.sinc

data/languages/21064NT.sla: data/languages/21064NT.slaspec data/languages/alpha.sinc

data/languages/21164VMS.sla: data/languages/21164VMS.slaspec data/languages/alpha.sinc

data/languages/21164UNIX.sla: data/languages/21164UNIX.slaspec data/languages/alpha.sinc

data/languages/21164NT.sla: data/languages/21164NT.slaspec data/languages/alpha.sinc

data/languages/21264VMS.sla: data/languages/21264VMS.slaspec data/languages/alpha.sinc

data/languages/21264UNIX.sla: data/languages/21264UNIX.slaspec data/languages/alpha.sinc

data/languages/21264NT.sla: data/languages/21264NT.slaspec data/languages/alpha.sinc

data/languages/21364VMS.sla: data/languages/21364VMS.slaspec data/languages/alpha.sinc

data/languages/21364UNIX.sla: data/languages/21364UNIX.slaspec data/languages/alpha.sinc

data/languages/21364NT.sla: data/languages/21364NT.slaspec data/languages/alpha.sinc

%.sla: %.slaspec
	/abuild/projects/Ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh_dbg $<
	sleigh -u $< $@

test:
	make -C tests

clean:
	rm -rf data/languages/*.sla
	make -C tests clean
