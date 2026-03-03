CC=gcc
BPFCC=clang
BPFLLC=llc
CPROG = bpf_test

# 1. Check if BPF_PROG is defined. If not, 'make' will error out immediately.
ifneq ($(MAKECMDGOALS),clean)
ifndef BPF_PROG
$(error BPF_PROG is undefined. Usage: make BPF_PROG=path/to/prog.txt)
endif
endif

CFLAGS = -DBPF_PROG_PATH="\"$(BPF_PROG)\""

all: $(CPROG)

bpf_test: bpf_test.o libbpf.o
	$(CC) $^ -o $@
	bash perm.sh

bpf_test.o: bpf_test.c $(BPF_PROG)
	$(CC) $(CFLAGS) -c bpf_test.c -o $@
 
allow_ptr_leaks: $(CPROG)
	bash perm.sh allow_ptr_leaks

%.o: %.c
	$(CC) -c $< -o $@

clean:
	rm -f *.o *.o.s
	rm -f $(CPROG)
