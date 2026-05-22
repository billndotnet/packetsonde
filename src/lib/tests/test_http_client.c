/* src/lib/tests/test_http_client.c */
#include "http_client.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static void test_url_parse(void) {
    struct ps_url u;
    assert(ps_url_parse("https://central.example:8700/api/v1/packetsonde/register", &u) == 0);
    assert(strcmp(u.scheme, "https") == 0);
    assert(strcmp(u.host, "central.example") == 0);
    assert(u.port == 8700);
    assert(strcmp(u.path, "/api/v1/packetsonde/register") == 0);

    assert(ps_url_parse("http://192.0.2.10:8700/x", &u) == 0);
    assert(u.port == 8700 && strcmp(u.scheme, "http") == 0);

    /* default ports */
    assert(ps_url_parse("https://h/p", &u) == 0 && u.port == 443);
    assert(ps_url_parse("http://h", &u) == 0 && u.port == 80 && strcmp(u.path, "/") == 0);
    assert(ps_url_parse("ftp://h/x", &u) == -1);
}

static void test_build_request(void) {
    struct ps_url u; ps_url_parse("http://h:8700/r", &u);
    char buf[1024];
    int n = ps_http_build_request(buf, sizeof buf, "POST", &u, "{\"a\":1}", NULL);
    assert(n > 0);
    assert(strstr(buf, "POST /r HTTP/1.1\r\n"));
    assert(strstr(buf, "Host: h:8700\r\n"));
    assert(strstr(buf, "Content-Type: application/json\r\n"));
    assert(strstr(buf, "Content-Length: 7\r\n"));
    assert(strstr(buf, "Connection: close\r\n"));
    assert(strstr(buf, "\r\n\r\n{\"a\":1}"));
}

static void test_parse_response(void) {
    const char *raw = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n"
                      "Content-Length: 9\r\n\r\n{\"ok\":1}\n";
    int status; const char *body;
    assert(ps_http_parse_response(raw, strlen(raw), &status, &body) == 0);
    assert(status == 201);
    assert(strncmp(body, "{\"ok\":1}", 8) == 0);
}

int main(void) {
    test_url_parse(); test_build_request(); test_parse_response();
    printf("test_http_client: OK\n");
    return 0;
}
