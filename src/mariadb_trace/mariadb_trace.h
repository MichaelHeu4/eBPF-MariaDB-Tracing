#ifndef MARIADB_TRACE
#define MARIADB_TRACE

#define MAX_SQL_LEN 256

struct event {
  int mariadb_pid;
  unsigned long long duration;
  unsigned long long bytes_sent;
  char query[MAX_SQL_LEN];
};

#endif
