#include "probe_via.h"

#include "remote_session.h"

int ps_probe_via_run(int argc, char **argv,
                     const struct ps_args *opts,
                     struct ps_output *out) {
    if (argc < 1) return 2;
    /* argv[0] is the probe kind; argv[1..] are its arguments. The
     * verb-agnostic session machinery lives in remote_session.c. */
    return ps_remote_run("probe", argv[0], argc - 1, &argv[1], opts, out);
}
