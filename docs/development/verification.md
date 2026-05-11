# Verification

Use the root verification script for local pre-commit checks and CI jobs:

```powershell
./scripts/verify.ps1
```

The script runs these checks from a clean command entry point:

1. `go work sync`
2. `go test ./apps/xso-idp/... ./apps/sample-client/... ./packages/xso-go/...`
3. `npm ci` in `frontend/xso-login`
4. `npm run test` in `frontend/xso-login`
5. `npm run build` in `frontend/xso-login`

For faster local reruns after dependencies are already installed:

```powershell
./scripts/verify.ps1 -SkipFrontendInstall
```

CI should use the full command without `-SkipFrontendInstall` so dependency installation is checked against `package-lock.json`.

Generated protobuf assets are not configured yet. When protobuf generation is added, the verification script should also fail if generated files are stale.
