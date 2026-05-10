# XSO

XSO (Xingle Sign On) is a self-hosted Single Sign-On learning project focused on modern backend architecture, authentication flows, and reusable service integration.

The first implementation targets a Go monorepo with a browser-facing login page, backend service boundaries, protocol contracts, and a reusable Go SDK.

## Repository Layout

```txt
apps/
  xso-idp/          Identity Provider service
  sample-client/    Example service integrating with XSO
frontend/
  xso-login/        XSO-hosted login page
packages/
  xso-go/           Reusable Go SDK
proto/
  xso/              Protocol contracts
deploy/             Docker and future deployment assets
docs/               Architecture and implementation notes
```

## Initial Goals

- Centralized login experience hosted by XSO.
- Backend-to-backend validation through typed service contracts.
- Reusable Go SDK for authentication middleware and user context injection.
- Security-first session, redirect, and token handling.

## Development

```powershell
go work sync
go test ./apps/xso-idp/... ./apps/sample-client/... ./packages/xso-go/...
```

Run app modules directly:

```powershell
go run ./apps/xso-idp/cmd/xso-idp
go run ./apps/sample-client/cmd/sample-client
```

Open the static login prototype at `frontend/xso-login/public/index.html`.
