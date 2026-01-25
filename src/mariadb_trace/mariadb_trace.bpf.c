#include "mariadb_trace.h"
#include "../../vmlinux/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct active_query_t {
  u64 start_time;
  u64 bytes_sent;
  char query[MAX_SQL_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u32);
  __type(value, struct active_query_t);
} active_queries SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

SEC("uprobe//usr/sbin/"
    "mariadbd:_Z16dispatch_command19enum_server_"
    "commandP3THDPcjb")
int BPF_KPROBE(handle_dispatch_entry, void *arg0, void *arg1, char *packet) {
  u32 tid = bpf_get_current_pid_tgid();
  struct active_query_t info = {};

  info.start_time = bpf_ktime_get_ns();
  info.bytes_sent = 0;

  bpf_probe_read_user_str(&info.query, sizeof(info.query), packet);
  bpf_map_update_elem(&active_queries, &tid, &info, BPF_ANY);

  return 0;
}

SEC("uprobe//usr/sbin/mariadbd:my_net_write")
int BPF_KPROBE(handle_net_write, void *net, const void *packet, size_t len) {
  u32 tid = bpf_get_current_pid_tgid();

  struct active_query_t *info = bpf_map_lookup_elem(&active_queries, &tid);
  if (!info)
    return 0;

  info->bytes_sent += len;
  return 0;
}

SEC("uretprobe//usr/sbin/"
    "mariadbd:_Z16dispatch_command19enum_server_commandP3THDPcjb")
int BPF_KPROBE(handle_dispatch_return) {
  u32 tid = bpf_get_current_pid_tgid();

  struct active_query_t *info = bpf_map_lookup_elem(&active_queries, &tid);
  if (!info)
    return 0;

  u64 now = bpf_ktime_get_ns();
  int pid = bpf_get_current_pid_tgid() >> 32;

  struct event *ev;
  ev = bpf_ringbuf_reserve(&ringbuf, sizeof(*ev), 0);
  if (!ev) {
    bpf_map_delete_elem(&active_queries, &tid);
    return 0;
  }

  ev->bytes_sent = info->bytes_sent;
  ev->duration = now - info->start_time;
  ev->mariadb_pid = pid;

  __builtin_memcpy(&ev->query, &info->query, MAX_SQL_LEN);

  bpf_ringbuf_submit(ev, 0);
  bpf_map_delete_elem(&active_queries, &tid);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
