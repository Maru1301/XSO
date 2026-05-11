# Architecture Overview

XSO is designed as a hybrid authentication platform:

- Browsers interact with XSO through HTTP login, logout, and session endpoints.
- Service backends validate sessions and authority through typed backend contracts.
- The login frontend is hosted by XSO and must stay outside internal service logic.

The first implementation should keep the system small while preserving these boundaries.

Core workflow references:

- [Service provider registration](service-provider-registration.md)
- [PostgreSQL schema draft](../backend/postgresql-schema.md)
- [Redis-backed challenge and session cache design](../backend/redis-cache-design.md)
