# Backend Service Boundaries

## Identity Provider

Owns authentication, session management, and browser-facing login endpoints.

## Authorization

Owns role, group, and permission evaluation.

## Federation

Owns SAML-inspired assertion generation and future protocol-specific concerns.

## SDK

Provides reusable client, middleware, context, and token/session helpers for service integrations. It should not own business authorization rules.
