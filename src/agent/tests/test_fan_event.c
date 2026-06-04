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
    printf("test_fan_event: OK\n");
    return 0;
}
