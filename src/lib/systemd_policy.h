#ifndef PS_SYSTEMD_POLICY_H
#define PS_SYSTEMD_POLICY_H
#include <stddef.h>
#include <stdint.h>

#define PS_POL_MAX_PATHS 64
#define PS_POL_PATHLEN  256
enum ps_protect_system { PS_PROTSYS_NO=0, PS_PROTSYS_YES, PS_PROTSYS_FULL, PS_PROTSYS_STRICT };
enum ps_protect_home   { PS_PROTHOME_NO=0, PS_PROTHOME_RO, PS_PROTHOME_INACCESSIBLE };
struct ps_unit_policy {
    int known;
    enum ps_protect_system protect_system;
    enum ps_protect_home   protect_home;
    int private_tmp;
    int mdwe;
    int n_rw;    char rw   [PS_POL_MAX_PATHS][PS_POL_PATHLEN];
    int n_ro;    char ro   [PS_POL_MAX_PATHS][PS_POL_PATHLEN];
    int n_inacc; char inacc[PS_POL_MAX_PATHS][PS_POL_PATHLEN];
};

/* Parse `systemctl show <unit>` Key=Value text into *out. known=0 if no
 * FragmentPath (unit not found). Returns 0 (always; malformed lines ignored). */
int ps_unit_policy_derive(const char *systemctl_show_text, struct ps_unit_policy *out);

typedef int (*ps_unit_policy_loader)(const char *unit, char *out, size_t cap);
/* Cached lookup: returns a derived policy for `unit`, loading via `loader` on a
 * cold/expired entry (ttl_sec). now_sec is the caller's clock. Returns 0. */
int ps_unit_policy_get(const char *unit, uint64_t now_sec, uint64_t ttl_sec,
                       ps_unit_policy_loader loader, struct ps_unit_policy *out);

/* Real loader: `systemctl show <unit> -p ...` via popen (validated unit name). */
int ps_unit_policy_load_systemctl(const char *unit, char *out, size_t cap);
#endif
