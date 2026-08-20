# TDS GA7 Release Gate

Deterministic GitHub Actions release promotion policy endpoint.

[![TDS GA7 Release Gate](https://github.com/YOUR-GITHUB-USERNAME/YOUR-REPO/actions/workflows/release-gate.yml/badge.svg?branch=main)](https://github.com/YOUR-GITHUB-USERNAME/YOUR-REPO/actions/workflows/release-gate.yml)

## Endpoint

POST `/release-gate`

## Decision

The service returns:

```json
{
  "decision": "promote",
  "violations": []
}
