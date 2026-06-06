#ifndef PS_PROC_PROFILE_DELTA_H
#define PS_PROC_PROFILE_DELTA_H
#include "proc_profile.h"
enum ps_pp_apply { PS_PP_APPLY_OK = 0, PS_PP_APPLY_DESYNC };

int ps_pp_keyframe_json(const struct ps_pp_model *m, const char *host,
                        char *out, size_t cap);
int ps_pp_delta_json(struct ps_pp_model *m, char *out, size_t cap);
enum ps_pp_apply ps_pp_apply_json(struct ps_pp_model *m, const char *json);
#endif
