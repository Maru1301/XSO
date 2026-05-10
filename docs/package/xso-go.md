# xso-go

`packages/xso-go` is the reusable Go SDK for service integration.

Initial responsibilities:

- Read session credentials from incoming requests.
- Validate session information through the XSO backend boundary.
- Inject authenticated user data into request context.
- Keep framework-specific adapters separate from core validation logic.
