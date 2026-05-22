#ifndef PS_HTTP_CLIENT_H
#define PS_HTTP_CLIENT_H
#include <stddef.h>

struct ps_url { char scheme[8]; char host[256]; int port; char path[512]; };
struct ps_http_opts { int verify; const char *ca_cert; int timeout_s; };

int ps_url_parse(const char *url, struct ps_url *out);
int ps_http_build_request(char *buf, size_t cap, const char *method,
                          const struct ps_url *u, const char *body,
                          const char *extra_headers);
int ps_http_parse_response(const char *raw, size_t len, int *status_out,
                           const char **body_out);
int ps_http_request(const char *method, const char *url, const char *body,
                    const struct ps_http_opts *opts, int *status_out,
                    char *resp_buf, size_t resp_cap);

/* Same, with an extra request header block (e.g. "X-Foo: bar\r\n"). */
int ps_http_request_h(const char *method, const char *url, const char *body,
                      const char *extra_headers,
                      const struct ps_http_opts *opts, int *status_out,
                      char *resp_buf, size_t resp_cap);
#endif
