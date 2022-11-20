CC=gcc
BPFCC=clang
BPFLLC=llc

cprogs = bpf_test bpf_test_alu bpf_test_jmp

all: $(cprogs)
	bash perm.sh

allow_ptr_leaks: $(cprogs)
	bash perm.sh allow_ptr_leaks

%.o: %.c
	$(CC) -c $< -o $@

bpf_test_alu: bpf_test_alu.o libbpf.o
	$(CC) $^ -o $@

bpf_test_jmp: bpf_test_jmp.o libbpf.o
	$(CC) $^ -o $@

bpf_test: bpf_test.o libbpf.o
	$(CC) $^ -o $@

clean:
	rm -f *.o *.o.s
	rm -f $(cprogs)
