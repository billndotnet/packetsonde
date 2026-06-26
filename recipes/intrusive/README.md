# Intrusive recipes

Recipes in this directory perform **active / intrusive** checks — they submit
input to attempt access or exercise a weakness (e.g. default-credential auth
attempts), rather than passively reading what a service volunteers.

Policy (see the project's agent-dispatch tier model):

- These are **NOT** in the default agent dispatch allowlist.
- They are runnable **locally** under direct operator control, and are
  agent-dispatchable **only** when an agent is explicitly opted in to the
  intrusive tier (a separate, default-off allowlist the operator enables per
  node).
- Use only against systems you are authorized to test.

Passive detection recipes (e.g. `recipes/router-id.json`) live outside this
directory and are agent-dispatchable by default.
