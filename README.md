* Requires `apt-get install bison clang flex libelf-dev llvm`
* Tested on 5.6
* `make defconfig`
* `make` (probably not needed)
* `make headers_install`
* `cd samples/bpf`
* Modify Makefile to include your programs
* `make` compiles all bpf programs
* To remove an xdp program attached to an interface `sudo ip link set dev if_name xdp off`
