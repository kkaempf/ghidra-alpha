.PHONY: tests emu

GHIDRA_DIR ?= /usr/share/ghidra
PYTHON ?= python3

tests: *.hex
	./runtest 21064 VMS $^
	./runtest 21164 UNIX $^
	./runtest 21264 NT $^

emu:
	GHIDRA_INSTALL_DIR=$(GHIDRA_DIR) $(PYTHON) emutest.py

clean:
	rm -rf *.out
	rm -rf core.*
	rm -rf *~
