#ifndef PS_IFACE_ENUM_H
#define PS_IFACE_ENUM_H

/* Returns 1 if `name` should be excluded from capture: it is "lo" (always), or it
 * starts with any comma-separated token in `exclude_csv` (prefix match; NULL/empty
 * csv excludes only "lo"). */
int ps_iface_excluded(const char *name, const char *exclude_csv);

/* Enumerate the host's interfaces (getifaddrs), collect unique non-excluded names
 * into out[][64] up to `max`. Returns the count. */
int ps_iface_enumerate(const char *exclude_csv, char out[][64], int max);

#endif
