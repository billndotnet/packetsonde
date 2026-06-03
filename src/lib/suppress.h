#ifndef PS_SUPPRESS_H
#define PS_SUPPRESS_H

/* Coarse read-only suppression. `list` is a comma-separated set of entries;
 * each entry is either "<path-prefix>" or "<comm>:<path-prefix>".
 * Returns 1 if this access should be suppressed (dropped before enrichment),
 * 0 to keep. Writes/exec (is_read==0) are NEVER suppressed. */
int ps_suppress_match(const char *list, const char *comm, const char *path, int is_read);

#endif /* PS_SUPPRESS_H */
