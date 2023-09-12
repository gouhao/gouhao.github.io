/* 需要在 /etc/security/limits.conf 里加入下面2句:
 *
 * * soft memlock unlimited
 * * hard memlock unlimited
 *
 */
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

int main(int argc, char *argv[])
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	struct bpf_link *link = NULL;

	obj = bpf_object__open_file("hello_kern.o", NULL);
	if (libbpf_get_error(obj)) {
		printf("open bpf object failed!\n");
		return -1;
	}

	prog = bpf_object__find_program_by_name(obj, "bpf_prog1");
	if (!prog) {
		printf("can not find prog!\n");
		goto cleanup;
	}

	if (bpf_object__load(obj)) {
		printf("can not load!\n");
		goto cleanup;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		printf("attach failed!\n");
		goto cleanup;
	}

	pause();

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
