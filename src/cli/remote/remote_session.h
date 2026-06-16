#ifndef PS_REMOTE_SESSION_H
#define PS_REMOTE_SESSION_H

struct ps_args;
struct ps_output;

/* Run <kind> with <argv> on a remote agent over the agent_proto mTLS session.
 * `type` is the request frame type ("audit" or "probe"). Builds
 * {"type":<type>,"kind":<kind>,"args":[argv...],"via_chain":[...]}, connects,
 * exchanges hello, streams finding/log/error/bye, applies via_agent rewrite.
 * Returns the CLI exit code (same semantics as today's audit --via path). */
int ps_remote_run(const char *type, const char *kind, int argc, char **argv,
                  const struct ps_args *opts, struct ps_output *out);

#endif
