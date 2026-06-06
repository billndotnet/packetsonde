#include "fan_monitor.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sys/fanotify.h>

int main(void) {
    int is_read = -1;
    assert(strcmp(ps_fan_event_for_mask(FAN_OPEN_EXEC, &is_read), "exec") == 0);
    assert(is_read == 0);
    assert(strcmp(ps_fan_event_for_mask(FAN_CLOSE_WRITE, &is_read), "write") == 0);
    assert(is_read == 0);                                  /* writes never suppressed */
    assert(strcmp(ps_fan_event_for_mask(FAN_ACCESS, &is_read), "access") == 0);
    assert(is_read == 1);
    assert(strcmp(ps_fan_event_for_mask(FAN_OPEN, &is_read), "open") == 0);
    assert(is_read == 1);
    /* precedence: exec > write > access > open when bits combine */
    assert(strcmp(ps_fan_event_for_mask(FAN_OPEN | FAN_CLOSE_WRITE, &is_read), "write") == 0);
    assert(strcmp(ps_fan_event_for_mask(FAN_OPEN_EXEC | FAN_OPEN, &is_read), "exec") == 0);

    /* ps_fan_path_under_csv: the userspace subtree filter for mount-wide events */
    assert(ps_fan_path_under_csv("/etc/passwd", "/etc") == 1);           /* nested */
    assert(ps_fan_path_under_csv("/etc", "/etc") == 1);                  /* exact */
    assert(ps_fan_path_under_csv("/etc/ssh/sshd_config", "/etc") == 1);  /* deep */
    assert(ps_fan_path_under_csv("/etcfoo/x", "/etc") == 0);             /* boundary: no false prefix */
    assert(ps_fan_path_under_csv("/var/log/x", "/etc") == 0);            /* unrelated */
    assert(ps_fan_path_under_csv("/home/u/.bashrc", "/etc,/home") == 1); /* second of CSV */
    assert(ps_fan_path_under_csv("/srv/x", "/etc,/home") == 0);          /* none of CSV */
    assert(ps_fan_path_under_csv("/etc/passwd", "/etc/") == 1);          /* trailing slash tolerated */
    assert(ps_fan_path_under_csv("/anything", "") == 0);                 /* empty csv */
    assert(ps_fan_path_under_csv("/anything", NULL) == 0);               /* null csv */
    assert(ps_fan_path_under_csv("/x", "/") == 1);                       /* root matches all */
    printf("test_fan_event: OK\n");
    return 0;
}
