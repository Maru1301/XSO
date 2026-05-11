# XSO

XSO (Xingle Sign On) is a self-hosted Single Sign-On learning project focused on modern backend architecture, authentication flows, and reusable service integration.

The first implementation targets a Go monorepo with a browser-facing login page, backend service boundaries, protocol contracts, and a reusable Go SDK.

## Repository Layout

```txt
apps/
  xso-idp/          Identity Provider service
  sample-client/    Example service integrating with XSO
frontend/
  xso-login/        Vue 3 XSO-hosted login page
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
./scripts/verify.ps1
```

For a faster local rerun after frontend dependencies are already installed:

```powershell
./scripts/verify.ps1 -SkipFrontendInstall
```

Run app modules directly:

```powershell
go run ./apps/xso-idp/cmd/xso-idp
go run ./apps/sample-client/cmd/sample-client
```

`xso-idp` uses in-memory stores by default. Durable/cache backends can be enabled with environment variables:

```powershell
$env:XSO_DATABASE_URL="postgres://xso:xso@localhost:5432/xso?sslmode=disable"
$env:XSO_REDIS_ADDR="localhost:6379"
$env:XSO_REDIS_PASSWORD=""
go run ./apps/xso-idp/cmd/xso-idp
```

Run the Vue 3 login app:

```powershell
cd frontend/xso-login
npm install
npm run dev
```

Build the login app before running `xso-idp` locally:

```powershell
cd frontend/xso-login
npm run build
cd ../..
go run ./apps/xso-idp/cmd/xso-idp
```
