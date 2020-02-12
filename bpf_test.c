/*
  This program is used to test the output (r0) of bpf program.
  Replace the bpf program with `{183, 0, 0, 0, -1},{15, 0, 0, 0, 0},`
  Then, execute `make` and run `./bpf_test` to get the output value.

  Logic of this program: store the bpf program output, then put this 
  value into the key-value map where key is r0 (map[r0] = output).
  Finally, from userspace, use key r0 to get the value from key-value map 
  and print it. Noting that this bpf program is attached to eth0 raw socket, 
  so it is packet-driven, i.e., once there is a packet in eth0, this program 
  will be run. Thus, a 3s-waiting time is set.
*/

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <linux/bpf.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stddef.h>
#include "libbpf.h"

static int test_sock(void)
{
	int sock = -1, map_fd, prog_fd, i, key;
	long long value = 0, r0_cnt;

	map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value),
				256);
	if (map_fd < 0) {
		printf("failed to create map '%s'\n", strerror(errno));
		goto cleanup;
	}

	struct bpf_insn prog[] = {
		/* test program start */
		{183, 0, 0, 0, -1},{15, 0, 0, 0, 0},
		/* test program end */

		// store value of the test program output r0 in r9
		BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),

		// set the key is output r0 value
		BPF_MOV64_IMM(BPF_REG_0, BPF_REG_0),
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10), 
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */

		// get the value address of r0 in key-value map
		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),

		// if r0 is found in the map, then set the value as output
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
		BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_9, 0),

		// r0 is the return value
		BPF_MOV64_IMM(BPF_REG_0, 0), /* r0 = 0 */
		BPF_EXIT_INSN(),
	};

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog),
				"GPL", 0);
	if (prog_fd < 0) {
		printf("failed to load prog '%s'\n", strerror(errno));
		goto cleanup;
	}

	// Attempt to print the bpf_log_buf for verifier information
	printf("Log buffer:\n %s\n---\n", bpf_log_buf);

	sock = open_raw_sock("lo");

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
		       sizeof(prog_fd)) < 0) {
		printf("setsockopt %s\n", strerror(errno));
		goto cleanup;
	}

	sleep(3);
	key = BPF_REG_0;
	assert(bpf_lookup_elem(map_fd, &key, &r0_cnt) == 0);
		
	printf("r0: %llx %lld \n", r0_cnt, r0_cnt);


cleanup:
	/* maps, programs, raw sockets will auto cleanup on process exit */
	return 0;
}

int main(void)
{
	FILE *f;

	f = popen("ping -c5 localhost", "r");
	(void)f;

	return test_sock();
}
