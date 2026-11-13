# Engineering constraints

Hecate separates source evidence, model inference, synthetic samples and observed
telemetry. Models can still produce unsupported claims or invalid detections;
deterministic grounding, parsing and conversion reduce those risks rather than
eliminating review.

- Environment profiles must be verified by adopters. Generic OCSF references and
  bundled examples do not establish local field availability or telemetry coverage.
- Optional ATT&CK/backend dependencies affect capability. Keep Core and Runner in
  the same tested environment; inspect `attack status` and installed extras.
- A converted query or synthetic holdout pass does not prove live ingestion,
  alerting or a representative production false-positive rate.
- Catalog and source-extraction caches have different invalidation rules and
  lifetimes. They are not portable evidence or permanent hunt history.
- Current code changes affect new processes. Restart application services and
  reopen interactive monitors after deployment.
- Tests must not load operator dotenv files or contact external systems implicitly.
  Temporary fixtures and mocked transports are part of the test contract.

See [Runner's constraints](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/CHALLENGES.md)
for scheduler, publication, replay and BAS boundaries.
