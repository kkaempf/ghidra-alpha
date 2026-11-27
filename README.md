# Alpha processor description for Ghidra

This implements the Digital (DEC) Alpha family of processors for [Ghidra](https://ghidra-sre.org)

## Requirements

- Ghidra
- Knowledge on how to use Ghidra

## How to install
1. Download a [prebuilt ghidra-alpha release](https://github.com/kkaempf/ghidra-alpha/releases), or build it yourself.
1. Start Ghidra
1. File -> Install Extensions
1. Press the plus icon ("Add extension")
1. Choose the built or downloaded ghidra-alpha zip file
1. Restart Ghidra when prompted to load the extension properly

## Alternative installation

You can add `ghidra-alpha` directly to your Ghidra installation. Find the
`Ghidra/Processors` directory and create a symlink from there to your
`git` checkout.

### Example

Assuming that Ghidra is installed below `/usr/lib64/ghidra`, run the
following:

~~~
git clone https://github.com/kkaempf/ghidra-alpha.git
sudo ln -s `pwd`/ghidra-alpha /usr/lib64/ghidra/Ghidra/Processors/Alpha
~~~

Then start Ghidra. You now have three Alpha processors (21064, 21164,
21264) and three operating systems (DEC Unix, OpenVMS, Windows NT) to choose from.

## How to build

### With VS Code and Docker

Open the directory in a VS Code instance and then reopen it in a devcontainer.

In a new terminal window type
```
./gradlew
```

### Otherwise

As a prerequisite, you need to have a Ghidra installation somewhere (an actual
installation, not a copy of Ghidra source code!).

```
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./gradlew
```

or

```
./gradlew -Pghidra.dir=/path/to/ghidra
```

You can then find a built extension .zip in the `dist` directory.



## License

Licensed under the Apache License, Version 2.0.
