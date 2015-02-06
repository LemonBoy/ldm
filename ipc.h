#pragma once

void ipc_deinit (int fd);
int  ipc_init (int as_master);
char ipc_read_one (int fd);
int  ipc_read_line (int fd, char *line, int max_line_length);
int  ipc_sendf (int fd, const char *fmt, ...);
