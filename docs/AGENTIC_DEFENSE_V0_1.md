# Agentic Defense v0.1 — read-only candidate correlation

Status: experimental module, synthetic fixtures; no autonomous agents or response actions.

## Trust model

Inputs are user-supplied JSONL copies. The module computes SHA-256 of each input file and retains per-line source references. Hashes show byte consistency, not authenticated origin. It does not verify whether a red-team action occurred or whether a detector missed it. Timestamp skew, Docker NAT, and concurrent traffic can create false correlations. Matching events are reported as **candidate** only; all effectiveness conclusions remain **inconclusive**. This schema is not integrated into the existing GRC-OS CVP verifier or Evidence Vault.

## ARTEX JSONL export contract

ARTEX native APIs have not yet been adapted. An explicit, reviewed export must contain timestamp (timezone-aware ISO8601), kind (`execution` or `approval`), tool, source IP as *observed externally*, destination IP, and `requested_ports` list. Do not infer NAT source attribution from a container's internal IP. Do not copy API credentials to the exports.

## Usage

```bash
uv run grcctl defense correlate \
  --artex examples/artex.jsonl \
  --suricata examples/suricata.jsonl \
  --wazuh examples/wazuh.jsonl \
  --output evidence/defense/synthetic-correlation.json
```

Test fixtures are **synthetic illustrations** based on the types of observations in the lab, not imported raw ARTEX/Wazuh records.

## Next gates

1. Design an authenticated, least-privilege ARTEX exporter without copying its database or admin token into the defender.
2. Build a read-only Wazuh and Suricata exporter with data minimization and verification of timestamps and sources.
3. Resolve clock synchronization and NAT context; use unique exercise IDs and approval IDs for attribution.
4. Integrate signed manifests and authenticated evidence ingestion before any real security telemetry enters GRC-OS's evidence store.
5. Only then add LLM investigations and human-approved response mechanisms.
