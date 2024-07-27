# LKM (Loadable Kernel Module)
This repository contains the experiment setup and prototype implementation of our thesis: Utilize Arm Pointer Authentication and Stack Unwinding to Protect System call Usage and Control Flow

## Environment requirements
The instructions in this document are based on Apple Mac Mini M1

- Kernel version: Asahi Linux 6.3.0-11
- CPU Architecture: Aarch64
- DRAM: 8GB

We also have conducted experiments using mainline Linux 6.3-rc7. Therefore, you can test the module by qemu.


## Build module
```
make
```

## Install module
```
make ins
```

## Remove module
```
make rm
```
