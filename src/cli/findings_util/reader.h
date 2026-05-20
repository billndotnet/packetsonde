#ifndef PS_FINDING_READER_H
#define PS_FINDING_READER_H

#include "finding.h"
#include <stddef.h>

struct ps_finding_lite {
    char id[64];
    char run_id[64];
    char kind[128];
    char source[128];
    char target[280];
    char title[256];
    enum ps_severity severity;
};

int ps_finding_parse_line(const char *line, struct ps_finding_lite *out);

#endif
