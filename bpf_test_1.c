/*
  This program is used to test the output (r0) of bpf program. 
  Replace `{183, 0, 0, 0, 1},...,{183, 9, 0, 0, 10},` with the bpf program. 
  Then, run `make` and `./bpf_test` to get the output value.

  The logic of this program: store the bpf program output, then put 
  this value into the key-value map where the key is `0` (map[0] = output). 
  Finally, from userspace, use key `0` to get the value (map[0]) from the 
  key-value map and print it. Noting that this bpf program is attached 
  to eth0 raw socket, so it is packet-driven, i.e., once there is a packet 
  in eth0, this program will be run. Thus, a 3s-waiting time is set.
*/

#include <assert.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stddef.h>
#include "libbpf.h"

// #define DEBUG

#define MAP_STORE(r_i)                                                         \
        BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_10, -(r_i + 1) * size),         \
        BPF_MOV64_IMM(BPF_REG_0, r_i),                                         \
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -10 * size - 4),             \
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),                                  \
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -10 * size -4),                      \
        BPF_LD_MAP_FD(BPF_REG_1, map_fd),                                      \
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),   \
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),                                 \
        BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_9, 0),                          \

static int test_bpf_prog_output(void)
{
	int sock = -1, map_fd, prog_fd, i, key;
	long long value = 0, val[10];

	map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value),
				256);
	if (map_fd < 0) {
		printf("failed to create map '%s'\n", strerror(errno));
		goto cleanup;
	}

	int size = 8;

	// A placeholder for the bpf program
	struct bpf_insn prog[] = {
		#include "bpf_prog.txt"
	};

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog),
				"GPL", 0);

	// Attempt to print the bpf_log_buf for verifier information
	printf("Log buffer:\n %s\n---\n", bpf_log_buf);

	if (prog_fd < 0) {
		printf("failed to load prog '%s'\n", strerror(errno));
		goto cleanup;
	}

	sock = open_raw_sock("lo");

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
		       sizeof(prog_fd)) < 0) {
		printf("setsockopt %s\n", strerror(errno));
		goto cleanup;
	}

	sleep(3);

	for (int i = 0; i < 10; i++) {
		key = i;
		assert(bpf_lookup_elem(map_fd, &key, &val[0]) == 0);
		printf("r%d: %llx %lld \n", i, val[0], val[0]);	
	}

cleanup:
	/* maps, programs, raw sockets will auto cleanup on process exit */
	return 0;
}

int main(void)
{
	FILE *f;

	f = popen("ping -c5 localhost", "r");
	(void)f;

	return test_bpf_prog_output();
}
