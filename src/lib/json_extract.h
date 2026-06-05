#ifndef PS_JSON_EXTRACT_H
#define PS_JSON_EXTRACT_H
#include <stddef.h>
/* Find the first occurrence of "<key>":"<value>" in json and write the
 * UNESCAPED value into out. Returns the unescaped length (excluding NUL), or
 * -1 if the key is absent or the value is malformed/over-long. Handles the
 * JSON string escapes ps_json emits: \" \\ \/ \n \r \t \b \f \uXXXX. */
int ps_json_extract_string(const char *json, const char *key, char *out, size_t cap);

/* Extract an integer value ("<key>":<int>) into *out. Returns 0 on success,
 * -1 if the key is absent or its value isn't a bare integer. */
int ps_json_extract_int(const char *json, const char *key, long *out);
#endif
