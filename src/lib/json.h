#ifndef PS_JSON_H
#define PS_JSON_H

#include <stddef.h>
#include <stdint.h>

struct ps_json {
    char   *buf;
    size_t  cap;
    size_t  len;
    int     depth;
    int     needs_comma;
    int     error;
};

void ps_json_init(struct ps_json *j, char *buf, size_t cap);

void ps_json_object_begin(struct ps_json *j);
void ps_json_object_end(struct ps_json *j);
/* Begin a nested object as the value of `key`: emits `"key":{`. Close with
 * ps_json_object_end. (object_begin alone emits `{` for root / array elements.) */
void ps_json_key_object_begin(struct ps_json *j, const char *key);
void ps_json_array_begin(struct ps_json *j, const char *key);
void ps_json_array_end(struct ps_json *j);

void ps_json_key_string(struct ps_json *j, const char *key, const char *val);
void ps_json_key_int(struct ps_json *j, const char *key, int64_t val);
void ps_json_key_double(struct ps_json *j, const char *key, double val);
void ps_json_key_bool(struct ps_json *j, const char *key, int val);
void ps_json_key_null(struct ps_json *j, const char *key);

void ps_json_array_string(struct ps_json *j, const char *val);
void ps_json_array_double(struct ps_json *j, double val);

int ps_json_finish(struct ps_json *j);

#endif
