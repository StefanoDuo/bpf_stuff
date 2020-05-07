* Requires `apt-get install make gcc libssl-dev bc libcap-dev gcc-multilib libncurses5-dev pkg-config libmnl-dev graphviz bison clang flex libelf-dev llvm`
* Tested on 5.6
* `make defconfig`
* `make headers_install`
* `cd samples/bpf`
* Modify Makefile to include your programs
* `make` compiles all bpf programs
* To remove an xdp program attached to an interface `sudo ip link set dev if_name xdp off`
* `sudo ./xdp_drop lo 127.0.0.1` and `ping 127.0.0.1` to check if everything works
* `ip netns add net1`, `ip netns add net2` to create 2 network namespaces
* `ip link add veth1 netns net1 type veth peer name veth2 netns net2` create veth pair between the 2 netns
* `ip netns exec net1 bash` to open a shell inside net1
* `ip addr add 192.168.1.1/24 dev veth1`
* `ip link set dev veth1 up`
