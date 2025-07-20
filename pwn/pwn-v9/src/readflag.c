#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>

int main ()
{
	int fd = open("/flag", O_RDONLY);
	if (fd < 0) {
		err(1, "Failed to open /flag");
	}

	char flag[0x100];
	memset(flag, 0, sizeof(flag));

	size_t n;
	if ((n = read(fd, flag, sizeof(flag) - 1)) < 0) {
		err(1, "Failed to read from /flag");
	}

	if (n == 0) {
		errx(1, "No data read from /flag");
	}

	flag[n] = '\0';
	flag[strcspn(flag, "\n")] = '\0';
	puts(flag);
}
