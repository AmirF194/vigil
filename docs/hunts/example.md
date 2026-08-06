---
name: Cloud credential compromise
hypotheses:
  - A valid cloud credential is being used from infrastructure the identity has never authenticated from before
  - The credential was obtained from an endpoint compromise rather than a phished login
scope:
  tenant: acme
  earliest: "-7d"
  latest: now
attack_techniques:
  - T1078.004
  - T1552.001
data_domains:
  - cloud_audit
  - identity
  - endpoint_process
budgets:
  max_iterations: 12
  max_cost_usd: 15.0
worker_hints:
  preferred_agents:
    - threat_hunter
    - network_analyst
    - threat_intel
---

# Cloud credential compromise

A hypothesis-driven hunt over the demo dataset. The trail is deliberately
multi-domain: a cloud audit anomaly should lead into identity logs and then
into endpoint process telemetry, so the cross-domain pivot is exercised rather
than a single-source confirmation.

Ground truth for the demo scenario is verified manually against the dataset's
answer key. A hypothesis reaches `proven` only after the disconfirmation pass
(#07); until then it stays `active` or resolves `inconclusive`.
