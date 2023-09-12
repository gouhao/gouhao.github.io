#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

# define SEC(NAME) __attribute__((section(NAME), used))

SEC("tracepoint/syscalls/sys_enter_kill")
int bpf_prog1(void *ctx)
{
	bpf_printk("hello bpf!\n");
	return 0;
}

char _license[] SEC("license") = "GPL";
