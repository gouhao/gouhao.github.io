#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
	int fd;

	fd = open("testfile", O_CREAT|O_TRUNC|O_RDWR, 0777);
	if (fd < 0) {
		printf("create file error\n");
	} else {
		printf("create file success\n");
		close(fd);
	}

	return 0;
}
