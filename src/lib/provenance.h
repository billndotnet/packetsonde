#ifndef PS_PROVENANCE_H
#define PS_PROVENANCE_H
#include <stddef.h>
#include "activity_record.h"

/* Provenance configuration: which path roots make a write/exec "interesting".
 * Path lists are comma-separated absolute prefixes (no trailing slash needed).
 * A NULL or empty list matches nothing. enabled=0 disables all classification. */
struct ps_prov_cfg {
    int enabled;
    const char *transient_paths;   /* e.g. "/tmp,/var/tmp,/dev/shm,/run,/home" */
    const char *sensitive_paths;   /* e.g. "/etc/cron.d,/etc/systemd/system,..." */
};

/* Classify one file event. event is the activity event string ("write"|"exec"|
 * "open"|"access"). path is the absolute file path. mode is the file's st_mode
 * (only consulted for write_executable; pass 0 when unknown/irrelevant).
 * Returns one of the static strings "write_executable", "write_sensitive_path",
 * "exec_from_transient", or "" when the event is not a provenance trigger.
 * Never returns NULL. */
const char *ps_provenance_classify(const char *event, const char *path,
                                   unsigned int mode, const struct ps_prov_cfg *cfg);

/* Build the detect.file_provenance observation bundle JSON from a parsed
 * activity record + trigger string + host name into out (cap bytes). Derives
 * session_src_ip from the first ancestor-owned ESTABLISHED tcp socket. Returns
 * bytes written (>0) or -1 on overflow/bad args. Pure (no I/O). */
int ps_provenance_build_record(const struct ps_activity *a, const char *trigger,
                               const char *host, char *out, size_t cap);

#endif /* PS_PROVENANCE_H */
