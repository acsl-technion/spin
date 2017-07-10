```
    _,   ,_____, __      __,_ __ ___ __ 
   / |  /   (   ( /     (  ( /  ( ( /  )
  /--| /     `.  /       `. /--' / /  / 
_/   |(___/(___(/___/  (___/   _/_/  (_ 
```

Tested on Ubuntu 15.04 with Linux kernel 3.19.0-47

Includes:
1. spindrv kernel module
2. libspin LD_PRELOAD library
3. patched nvme module

## Install
Make sure no NVME FS are mounted
unload the nvme module

In spindrv:
```bash
$ make
$ sudo make install
```

In spinnvme
```bash
$ make
$ sudo insmod nvme.ko
```

In libspin
```bash
$ make
```

Then run applications which utilize pread64 with LD_PRELOAD=<libspin.so> command

NOTE:
This is an experimental POC and is provided AS IS.
Feel free to use/modify/distribute,
If used, please retain this disclaimer and cite

"SPIN: Seamless Operating System Integration of Peer-to-Peer DMA Between SSDs and GPUs",
Bergman S, Brokhman T, Cohen T, Silberstein M.
USENUX ATC 17, July 2017, Santa Clara, USA
