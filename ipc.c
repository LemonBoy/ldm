#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define IPC_SOCKET  "/run/ldm.socket"

void
ipc_deinit (int fd)
{
	if (fd >= 0)
		close (fd);
	unlink (IPC_SOCKET);
}

int
ipc_init (int as_master)
{
	int sock;
	int flags;
	struct sockaddr_un so;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return -1;
	}

	memset(&so, 0, sizeof(struct sockaddr_un));
	so.sun_family = AF_UNIX;
	strncpy(so.sun_path, IPC_SOCKET, sizeof(so.sun_path));

	if (as_master) {
		// Make sure that there are no leftovers
		unlink (IPC_SOCKET);

		// The master waits for the slaves to connect
		if (bind(sock, (struct sockaddr *)&so, sizeof(struct sockaddr_un)) < 0) {
			perror("bind");
			return -1;
		}

		// Make the sock non-blocking
		flags = fcntl(sock, F_GETFL, 0);
		if (flags < 0) {
			perror("fcntl");
			return -1;
		}

		if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
			perror("fcntl");
			return -1;
		}
	}
	else {
		// The slave connects to the master
		if (connect(sock, (struct sockaddr *)&so, sizeof(struct sockaddr_un)) < 0) {
			perror("connect");
			return -1;
		}
	}

	return sock;
}

char
ipc_read_one (int fd)
{
	char resp;

	if (fd < 0)
		return 0;

	if (read(fd, &resp, 1) != 1) {
		perror("read");
		return 0;
	}

	return resp;
}

int
ipc_read_line (int fd, char *line, int max_line_length)
{
	int p;

	if (fd < 0 || !line)
		return 0;

	for (p = 0; p < max_line_length - 1; p++) {
		if (read(fd, &line[p], 1) != 1) {
			perror("read");
			break;
		}

		if (line[p] == '\n')
			break;
	}

	line[p] = '\0';

	// Don't take into account the \n
	return p? p - 1: 0;
}

int
ipc_sendf (int fd, const char *fmt, ...)
{
	va_list args, args_;
	int fmt_length;
	char *buf;

	va_start(args, fmt);

	// Make a copy since the first vsnprintf call modifies it
	va_copy(args_, args);

	// Obtain the final string length first
	fmt_length = vsnprintf(NULL, 0, fmt, args_);
	if (fmt_length < 0) {
		perror("vsprintf");
		va_end(args);
		return 0;
	}

	buf = malloc(fmt_length + 1);
	if (!buf) {
		perror("errno");
		va_end(args);
		return 0;
	}

	vsnprintf(buf, fmt_length + 1, fmt, args);

	// Don't send the trailing NULL
	if (write(fd, buf, fmt_length) != fmt_length) {
		perror("write");
		free(buf);
		va_end(args);
		return 0;
	}

	free(buf);
	va_end(args);

	return fmt_length;
}
