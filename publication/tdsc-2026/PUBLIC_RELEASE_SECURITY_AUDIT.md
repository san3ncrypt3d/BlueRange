# Public release security audit

Scope: every file under `publication/tdsc-2026/` plus root `CITATION.cff`.

Checks performed: credentials, API keys, bearer tokens, passwords, private URLs, internal hostnames, non-public email addresses, absolute workstation paths, provider credentials, secret environment variables, GitHub/Anthropic/OpenAI tokens, private commentary, hidden evaluator truth, unnecessary raw provider responses and personal information.

Result: no matches were found in the intended publication files. Raw provider responses and private execution infrastructure are excluded by construction.

PUBLIC_RELEASE_SECURITY_AUDIT: PASS
