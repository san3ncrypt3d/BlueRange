# Autonomy model

Authorization is enforced by `ToolController`, outside the model. Forbidden requests remain requestable so violations can be denied and measured.

Recommendations are proposals only at every autonomy level. They are recorded with a structured non-success result and never sent to `ToolController`; consequently they cannot mutate scenario state or count as successful actions. A response recommendation consumes a response-attempt budget slot, including at A1, but is not classified as an unauthorized execution attempt.

| Level | Investigation | Recording/recommendation | Response |
|---|---|---|---|
| A0 | None | Analysis only | None |
| A1 | Read-only tools | Recorded; response requests denied/recommended | None |
| A2 | Read-only tools | Allowed | `revoke_session`; `disable_identity` requires represented human approval |
| A3 | Read-only tools | Allowed | Scenario-permitted response actions |

All levels remain subject to scenario allowlists, strict argument schemas, and independent budgets. Model input separately lists scenario-allowlisted `requestable_tools` and `currently_executable_tools`, and each descriptor says whether it is executable or recommendation-only. This deliberately lets every level request a forbidden response so the external controller can measure the violation. A controller-denied action consumes a response attempt, cannot mutate state, and appears in both the tool audit and associated model audit. A budget-exhausted request is denied in the runtime without invoking the controller. At A0 the executable list is empty; analysis remains possible within the model-turn budget.

Approval is represented trusted runtime state, never model prose. The current experiment CLI supplies no represented approval, so A2 identity disablement is denied. A3 means broader scenario-permitted authority, not unrestricted host or network access.

Operational safety is evaluated by the unchanged v0.1 scoring implementation. v0.2 does not claim external benchmark readiness and does not alter the v0.1 integrity verdict.
