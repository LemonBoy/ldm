#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include "ipc.h"

int
ipc_send (int fd, char type, char *arg)
{
	char *fmt;
	char *opt;
	char tmp[4096];
	int r;

	if (fd < 0)
		return 0;

	fmt = opt = NULL;

	switch (type) {
		case 'r':
			fmt = "R%s";
			opt = arg;
			break;

		case 'l':
			fmt = "L";
			opt = NULL;
			break;

		default:
			fprintf(stderr, "Unknown ipc command %c\n", type);
			return 0;
	}

	if (!ipc_sendf(fd, fmt, opt)) {
		fprintf(stderr, "Could not communicate with the daemon! Is ldm running?\n");
		return 0;
	}

	switch (type) {
		case 'r':
			// Receive the result code
			r = ipc_read_one(fd);

			if (r == '+')
				printf("Operation completed successfully\n");
			else
				printf("The operation didn't complete successfully\n");

			return (r == '+');

		case 'l':
			// Dump all the received lines to stdout
			while (1) {
				r = ipc_read_line(fd, tmp, sizeof(tmp));
				if (!r)
					break;
				printf("%s\n", tmp);
			}

			return 1;
	}

	return 0;
}

void
usage ()
{
	printf("ldmc %s\n", VERSION_STR);
	printf("2015-2016 (C) The Lemon Man\n");
	printf("\t-r <path> Remove a mounted device\n");
	printf("\t-l List the mounted devices\n");
	printf("\t-h Show this help\n");
}

int
main (int argc, char **argv)
{
	int opt;
	int ipc_fd;
	int ret;

	if (argc == 1) {
		usage ();
		return EXIT_FAILURE;
	}

	ret = EXIT_SUCCESS;

	while ((opt = getopt(argc, argv, "hlr:")) != -1) {
		switch (opt) {
			case 'l':
			case 'r':
				ipc_fd = ipc_init(0);

				// Could not open the ipc socket
				if (ipc_fd < 0)
					return EXIT_FAILURE;

				// Propagate the error code to the exit status
				if (!ipc_send(ipc_fd, (char)opt, optarg))
					ret = EXIT_FAILURE;

				close(ipc_fd);
				break;

			default:
			case 'h':
				usage ();
		}
	}

	return ret;
}
