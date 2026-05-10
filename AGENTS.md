# Repository Instructions

If the response needs to be presented in Chinese, use traditional Chinese with Taiwanese terminology and usage.

## Project Context

XSO (Xingle Sign On) is a learning-oriented, self-hosted SSO system. The intended architecture is a Go monorepo with:

- `apps/xso-idp`: Identity Provider service.
- `apps/sample-client`: sample service integrating with XSO.
- `packages/xso-go`: reusable Go SDK for service integration.
- `proto/xso`: protocol contracts.
- `frontend/xso-login`: XSO-hosted browser login page.
- `deploy`: local and future deployment assets.
- `docs`: architecture and implementation notes.

Project source notes live outside this repo at `C:\Users\HWNQ\workspace\Note.md\Projects\XSO`.

## Engineering Defaults

- Preserve the security boundary between browser-facing HTTP endpoints and internal gRPC/service contracts.
- Keep authentication logic on the backend. The login frontend must not verify passwords, evaluate permissions, sign tokens, or store session tokens in browser storage.
- Prefer small, explicit Go packages over broad abstractions while the project is young.
- Keep the Go SDK framework-agnostic; standard `net/http` support can be the first integration target.
- Avoid adding infrastructure dependencies until there is code that needs them.

## Verification

- Run `go test ./apps/xso-idp/... ./apps/sample-client/... ./packages/xso-go/...` from the workspace root.
- For frontend changes, prefer static validation first unless a package manager workflow has been added.
