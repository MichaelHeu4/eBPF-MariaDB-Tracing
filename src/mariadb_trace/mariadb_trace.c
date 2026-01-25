#include "mariadb_trace.h"
#include "mariadb_trace.skel.h"
#include "mariadb_trace_settings.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

static int stop = 0;

void sig_handler(int signo) { stop = 1; }

int is_dump_tool(const char *query) {
  if (strstr(query, "/*!") && strstr(query, "SQL_NO_CACHE"))
    return 1;
  return 0;
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

  if (is_suspicious) {
    printf("[%s] PID: %d | Time: %.2f ms | Bytes: %llu | Query: %s\n", "ALERT",
           e->mariadb_pid, duration_ms, e->bytes_sent, e->query);
  }

  if (ALERT_ENABLE_INFO_LOGGING && !is_suspicious) {
    printf("[%s] PID: %d | Time: %.2f ms | Bytes: %llu | Query: %s\n", "INFO ",
           e->mariadb_pid, duration_ms, e->bytes_sent, e->query);
  }

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
  mariadb_trace_bpf__destroy(skel);

  return err < 0 ? -err : 0;
}
