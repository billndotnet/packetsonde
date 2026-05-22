#include "json.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char buf[512];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof buf);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "a", "1");
    ps_json_key_object_begin(&j, "tls");          /* nested object as a key value */
    ps_json_key_string(&j, "version", "1.3");
    ps_json_array_begin(&j, "alpn");
    ps_json_array_string(&j, "h2");
    ps_json_array_end(&j);
    ps_json_object_end(&j);                        /* close tls */
    ps_json_array_begin(&j, "hosts");              /* array of objects */
    ps_json_object_begin(&j); ps_json_key_string(&j, "ip", "10.0.0.1"); ps_json_object_end(&j);
    ps_json_object_begin(&j); ps_json_key_string(&j, "ip", "10.0.0.2"); ps_json_object_end(&j);
    ps_json_array_end(&j);
    ps_json_object_end(&j);
    assert(ps_json_finish(&j) > 0);
    assert(strcmp(buf,
        "{\"a\":\"1\",\"tls\":{\"version\":\"1.3\",\"alpn\":[\"h2\"]},"
        "\"hosts\":[{\"ip\":\"10.0.0.1\"},{\"ip\":\"10.0.0.2\"}]}") == 0);
    printf("test_json: OK\n");
    return 0;
}
