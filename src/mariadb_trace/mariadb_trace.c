#include "mariadb_trace.h"
#include "mariadb_trace.skel.h"
#include "mariadb_trace_settings.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

static int stop = 0;
FILE *log_file = NULL;

void sig_handler(int signo) { stop = 1; }

int is_dump_tool(const char *query) {
  if (strstr(query, "/*!") && strstr(query, "SQL_NO_CACHE"))
    return 1;
  return 0;
}

void get_timestamp(char *buffer, size_t size) {
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  strftime(buffer, size, "%Y-%m-%d %H:%M:%S", t);
}

void json_escape_string(char *dest, size_t dest_size, const char *src) {
  size_t d = 0;
  for (size_t s = 0; src[s] != '\0'; s++) {
    if (d >= dest_size - 3)
      break;

    char c = src[s];

    switch (c) {
    case '\"': // Anführungszeichen
      dest[d++] = '\\';
      dest[d++] = '\"';
      break;
    case '\\': // Backslash
      dest[d++] = '\\';
      break;
    case '\n': // Zeilenumbruch
      dest[d++] = '\\';
      dest[d++] = 'n';
      break;
    case '\r': // Carriage Return
      dest[d++] = '\\';
      dest[d++] = 'r';
      break;
    case '\t': // Tab
      dest[d++] = '\\';
      dest[d++] = 't';
      break;
    default:
      if ((unsigned char)c >= 32) {
        dest[d++] = c;
      }
      break;
    }
  }
  dest[d] = '\0';
}

int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct event *e = data;

  double duration_ms = e->duration / 1000000.0;

  int is_suspicious =
      (e->bytes_sent >= 1024 * 1024 * ALERT_QUERY_SIZE_MEGABYTES) ||
      (duration_ms >= ALERT_DURATION_MILLISECONDS);
  if (ALERT_DUMP) {
    is_suspicious = is_suspicious || is_dump_tool(e->query);
  }

  if (!ALERT_ENABLE_INFO_LOGGING && !is_suspicious) {
    return 0;
  }

  char time_str[32];
  char query_escaped[MAX_SQL_LEN * 2 + 1];

  json_escape_string(query_escaped, sizeof(query_escaped), e->query);
  get_timestamp(time_str, sizeof(time_str));

  fprintf(log_file,
          "{\"timestamp\": \"%s\", \"level\": \"%s\", \"pid\": %d,"
          "\"bytes\": %llu, \"duration_ms\": %.2f, "
          "\"query\": \"%s\"}\n",
          time_str, is_suspicious ? "ALERT" : "INFO", e->mariadb_pid,
          e->bytes_sent, duration_ms, query_escaped);

  fflush(log_file);
  return 0;
}

int main(int argc, char **argv) {
  struct mariadb_trace_bpf *skel;
  int err;

  // Set libbpf strict mode
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  // Set libbpf print function
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  // Initalize Log File
  log_file = fopen("/var/log/mariadb_dlp.log", "a");
  if (!log_file) {
    fprintf(stderr, "Failed to open log_file!\n");
    return 1;
  }

  // Open BPF program, returns the skeleton object
  skel = mariadb_trace_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  // Load and verify BPF program
  err = mariadb_trace_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  // Attach BPF program to tracepoint
  err = mariadb_trace_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  // After successful execution, print tracepoint output logs
  printf("Successfully started!\n");
  struct ring_buffer *rb = NULL;
  rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_event, NULL,
                        NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  printf("DLP Monitor running... Ctrl-C to stop.\n");

  while (!stop) {
    err = ring_buffer__poll(rb, 100 /* timeout ms */);
    if (err == -EINTR)
      err = 0;
    if (err < 0)
      break;
  }

cleanup:
  // Destroy BPF program
  ring_buffer__free(rb);
  fclose(log_file);
  mariadb_trace_bpf__destroy(skel);

  return err < 0 ? -err : 0;
}
