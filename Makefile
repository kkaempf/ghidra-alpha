all: nt unix vms analyzer test

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

SLEIGH ?= sleigh

%.sla: %.slaspec
	$(SLEIGH) $<
	$(SLEIGH) -u $< $@

test:
	make -C tests

# Java analyzer (gp-relative reference recovery) and ECOFF loader. Compiled
# against the jars of an installed Ghidra and packaged as lib/Alpha.jar, which
# Ghidra discovers automatically for this processor module.
GHIDRA_DIR ?= /usr/share/ghidra
GHIDRA_CP = $(shell find $(GHIDRA_DIR)/Ghidra -name '*.jar' | tr '\n' ':')
JAVA_SRC = $(shell find src/main/java -name '*.java')

analyzer: lib/Alpha.jar

lib/Alpha.jar: $(JAVA_SRC)
	rm -rf build/classes
	mkdir -p build/classes lib
	javac -cp "$(GHIDRA_CP)" -d build/classes $(JAVA_SRC)
	jar cf $@ -C build/classes .

clean:
	rm -rf data/languages/*.sla build lib/Alpha.jar
	make -C tests clean
