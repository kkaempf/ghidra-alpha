# Alpha processor description for Ghidra

This implements the Digital (DEC) Alpha family of processors for
[Ghidra](https://ghidra-sre.org)

# Requirements

- Ghidra
- Knowledge on how to use Ghidra

# Installation

`ghidra-alpha` must be added to your Ghidra installation. Find the
`Ghidra/Processors` directory and create a symlink from there to your
`git` checkout.

## Example

Assuming that Ghidra is installed below `/usr/lib64/ghidra`, run the
following:

~~~
git clone https://github.com/kkaempf/ghidra-alpha.git
sudo ln -s `pwd`/ghidra-alpha /usr/lib64/ghidra/Ghidra/Processors/Alpha
~~~

Then start Ghidra. You now have three Alpha processors (21064, 21164,
21264) to choose from.

# Testing

`make test` checks disassembly with sleigh-lift.

`make emutest` checks the byte-manipulation instructions in Ghidra's
p-code emulator. It needs [pyghidra](https://pypi.org/project/pyghidra/)
and a Ghidra install with this module linked in as above:

~~~
make emutest GHIDRA_DIR=/usr/lib64/ghidra PYTHON=/path/to/venv/bin/python
~~~
