clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c mariadb_trace.bpf.c -o mariadb_trace.bpf.o
bpftool gen skeleton mariadb_trace.bpf.o > mariadb_trace.skel.h
rm mariadb_trace.bpf.o
