#ifndef PS_CAPTURE_SESSION_H
#define PS_CAPTURE_SESSION_H

/*
 * Brain-side detect capture session.
 *
 * While a session is active, every emitted detect event (the same JSON line
 * the agent appends to the normal activity sink) is tee'd into a per-session
 * file: <capture_dir>/<session_id>.jsonl.  The capture directory is resolved
 * from the environment variable PS_DETECT_CAPTURE_DIR, defaulting to
 * /var/lib/packetsonde/captures, and is created (mkdir -p) when a session is
 * set.
 *
 * Thread-safety: all three calls take an internal mutex, so concurrent
 * set/clear/append are safe even though the brain currently drives them from
 * a single event-loop thread.
 */

/* Set the active session.  Copies session_id and mkdir -p's the capture dir.
 * Passing NULL or an empty id is equivalent to clearing the session. */
void ps_capture_session_set(const char *session_id);

/* Clear the active session (subsequent appends become noops). */
void ps_capture_session_clear(void);

/* If no session is active, returns 0 (noop).  Otherwise appends json_line
 * (ensuring exactly one trailing newline) to <dir>/<id>.jsonl and returns 1.
 * Returns 0 if the file cannot be opened. */
int ps_capture_session_append(const char *json_line);

#endif /* PS_CAPTURE_SESSION_H */
