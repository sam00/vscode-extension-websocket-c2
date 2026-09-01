# Security & Authorized Use

This repository contains a command-and-control (C2) agent implementation.
It is published for **authorized security testing only**:

- Red team engagements with written authorization
- Purple team / detection-engineering exercises on your own infrastructure
- Security research in controlled lab environments

## Rules of use

1. **Never** deploy this against systems you do not own or lack explicit
   written permission to test.
2. **Never** commit real infrastructure details (hosts, keys, payload UUIDs)
   to this repository. `config.json` is gitignored — keep it that way.
3. Operators are responsible for compliance with all applicable laws and
   organizational policies.

## Reporting issues

If you discover a vulnerability in this tool itself, open a private security
advisory rather than a public issue when exploitation details are sensitive.
