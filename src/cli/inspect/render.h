#ifndef PS_INSPECT_RENDER_H
#define PS_INSPECT_RENDER_H
#include "proc_profile.h"
struct ps_inspect_stream { int started; };
void ps_inspect_stream_init(struct ps_inspect_stream *st);
void ps_inspect_stream_render(struct ps_inspect_stream *st, struct ps_pp_model *m,
                              const char *host);
void ps_inspect_tty_render(struct ps_pp_model *m, const char *host);
#endif
