# Architecture and evidence contract

The platform separates the live local model, sandbox execution, capture, independent verification, and post-incident analysis. LangGraph starts at a benchmark-specified retrieval, then alternates model requests and sandbox tools for at most three model turns. Benchmark attacks are evaluated inside simulated tool implementations: no model-selected shell command, email, payment, permission change, or remote request is executed on the host.

## Evidence version 1

Each JSONL event has schema_version, event_id, session_id, sequence, timestamp, type, actor, payload, parent_ids, previous_hash and hash. Event IDs are session ID plus a six-digit sequence. Times are UTC. The hash is SHA-256 over RFC 8785 canonical JSON of every field except hash. The first previous_hash is 64 zeros. Parent references must identify earlier events in the same session. Payloads are snapshotted on capture so later graph mutations cannot rewrite earlier evidence in memory.

Every ten events and at finalization, an Ed25519-signed checkpoint fixes the session ID, count, head and timestamp. A signed final manifest fixes the count, head, status and public-key fingerprint. A crash before this manifest yields an incomplete session. A failed model request can produce an intact, finalized session whose status is failed; cryptographic validity and successful execution are separate properties.

The signer stores its private PEM in .private/signing.pem. The public PEM at results/public_key.pem is the verifier trust input. Embedded bundle keys are compared with that external key and are never automatically trusted. SQL triggers discourage accidental changes to the events index. SQLite is a convenience cache, not an immutable or trusted storage device.

## Oracle and labels

The sandbox records execution receipts before returning tool results. The HTTP client records successful and failed requests and proposed calls. These receipts are saved separately from the recorder. Completeness compares required request/result pairs with those receipts, while required session, user and retrieval boundaries are checked separately. This establishes capture coverage of observable operations in this test harness, not access to model internals or proof that every possible production event was observed.

Attack presence comes from the scenario manifest. Action-violation truth comes from the runner's proposed calls and declared policy, independently of the detector's findings. A completed sandbox action is counted separately. Labels, attack categories, source attacker instructions and expected achievements never enter detector inputs. Detectors inspect selected observable event payloads and the policy; opaque case IDs are not features.

Policy-only and combined action detectors apply the same explicit allowlist, so equal performance is expected on action labels defined by that policy. This task verifies reliable reconstruction rather than demonstrating learned generalization. Injection-presence detection is a separate, harder heuristic task. Temporal links establish event order, not causal attribution.

The separate triage annotation module extracts destination arguments and synthetic-marker appearances in tool requests and model responses. It does not change the frozen classifier or its reported predictions. An observed destination is not proof of a real external transfer; a corresponding sandbox result distinguishes simulated execution from an unexecuted proposal.

## Custody and trust limits

Collection and CLI evidence exports append signed, hash-linked records to results/custody.jsonl. verify_custody verifies its signatures and ordering. Exports include a custody snapshot; the subsequent export receipt hashes the completed ZIP in the external custody log to avoid self-reference. GUI downloads include a snapshot of existing custody history and record the user's export action separately. After distribution, recipients have no original signing key: their export receipts use a separate key and chain under output/operator_audit, preserving the collector's original key and custody history.

An attacker can edit, delete, truncate, or replace stored events; the verifier detects inconsistency against an intact signed manifest and trusted key. The mechanism cannot recover destroyed evidence, prevent confidential data disclosure, identify a person cryptographically, establish trusted wall-clock time, or protect evidence if the signing key and every independent trust anchor are replaced. It does not implement forward-secure key evolution or distributed transparency witnesses. A complete replacement by another legitimately signed session requires an independently retained expected session ID or manifest digest to detect substitution.

## Reproduction boundaries

Saved-trace evaluation is deterministic and requires no model. Fresh live generation uses the pinned model with explicit seeds, but GPU kernels and sampling may produce different responses. Regenerated evidence must go to a separate output root, with its own key pair, preserving the submitted reference evidence. Resume preserves incomplete attempts under results/interrupted and rebuilds the non-authoritative SQLite index when necessary.
