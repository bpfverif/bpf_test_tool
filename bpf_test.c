/*
  This program is used to test a bpf program (provided in macro format), in 
  bpf_prog.txt. Run `make` and `./bpf_test` to get the verifier logs. 
*/

#include <assert.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stddef.h>
#include "libbpf.h"

static int test_bpf_prog_output(void)
{
	int prog_fd;

	struct bpf_insn prog[] = {
		#include BPF_PROG_PATH
	};

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog),
				"GPL", 0);

	// Attempt to print the bpf_log_buf for verifier information
	printf("Log buffer:\n---\n %s\n---\n", bpf_log_buf);

	if (prog_fd < 0) {
		printf("failed to load prog '%s'\n", strerror(errno));
		goto cleanup;
	}

	printf("success.\n");

cleanup:
	/* maps, programs, raw sockets will auto cleanup on process exit */
	return 0;
}

int main(void)
{
	return test_bpf_prog_output();
}
