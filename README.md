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

# Analyzer and loaders

`make analyzer` builds `lib/Alpha.jar`, which Ghidra picks up from the
module. It adds a gp-relative reference analyzer and two loaders.

The "Alpha ECOFF (Tru64 UNIX)" loader handles Tru64 (Digital UNIX, DEC
OSF/1) executables and shared libraries. It reads symbols from the ECOFF
symbol table, `.dynsym`, and `.pdata`, and names calls to imports
through the GOT.

The "OpenVMS Alpha image" loader handles OpenVMS Alpha executables,
shareable images and executive images. It finds procedures through
their procedure descriptors, sets R27 to the descriptor on entry so the
decompiler follows calls through the linkage section, and names symbols
from the image's global symbol table.

Calls into shareable images (DECC$SHR, LIBRTL, SYS$PUBLIC_VECTORS and
so on) are named through the image's fixups. To resolve a symbol
vector offset to a name, the loader looks for the shareable image
beside the file being imported, then in each absolute directory in
Ghidra's library search paths (for example a copy of `SYS$LIBRARY`).
When an image cannot be found, the import is named `IMAGE_OFFSET`,
e.g. `DECC$SHR_46F0`.

Shareable images linked at address 0 and executive images can be loaded
at any base. The "Image base" option picks it (defaulting to 0x10000
for shareable images and 0xffffffff80000000 for executive images), and
the loader applies the image's relocations to match.
