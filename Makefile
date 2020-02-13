CC=gcc
BPFCC=clang
BPFLLC=llc

cprogs = bpf_test

all: $(cprogs)
	bash perm.sh

%.o: %.c
	$(CC) -c $< -o $@

bpf_test: bpf_test.o libbpf.o
	$(CC) $^ -o $@

clean:
	rm -f *.o *.o.s
	rm -f $(cprogs)
