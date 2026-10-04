# Detection Engineering Pipeline

## Structure
```
pipeline/
├── simulations/       YAML manifests (attack definition + expected telemetry)
├── rules/             Sigma YAML rules with full metadata
├── expected/          Expected telemetry per simulation (JSON)
├── results/           Run outputs (timestamped JSON)
├── tuning/            Tuning log (CSV: rule_id, change, fp_before/after, detection_preserved)
├── coverage/          ATT&CK Navigator layer (visual coverage map)
├── scripts/           Python evaluation pipeline
├── Makefile           make validate + make evaluate
└── README.md
```

## Quickstart
```bash
make validate    # Check all YAML/JSON syntax
make evaluate    # Query Splunk, check telemetry + detections, write results
```

## Lifecycle
1. Define attack → `simulations/SIM-XXX_<name>.yml`
2. Write Sigma rule → `rules/sigma_rules.yml`
3. Add expected telemetry → `expected/expected_events.json`
4. Run simulation → `python3 04-attacks/AttkXXX_psuedoattacks.*`
5. Evaluate → `make evaluate` → verdict: detected / partial / missed / telemetry_gap
6. If missed → fix rule → re-run simulation → record in `tuning/tuning_log.csv`
7. Publish → regenerated `coverage/navigator_layer.json`

## Verdicts
- **detected** — telemetry present, rule fired within TTD threshold
- **partial** — rule fired but late or missing context
- **missed** — telemetry present but rule didn't fire (write/fix rule)
- **telemetry_gap** — expected logs not in Splunk (fix forwarding/logging)

## Metrics (from results JSON)
- Coverage: techniques detected / techniques simulated
- TTD: alert_time − execution_time (seconds)
- FP rate: false positives per rule per 24h (from benign baseline run)