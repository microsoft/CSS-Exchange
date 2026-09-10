# EXO TSG core rules

These rules define reusable safety and evidence requirements for Exchange Online troubleshooting skills. They are prototyped with the RBA skill and are intended to move to a shared Microsoft Exchange Support Skills location after the pattern is validated.

## Rule ranges

| Range | Rule group |
|---|---|
| TSG000–TSG099 | Authority and truthfulness |
| TSG100–TSG199 | Evidence validation and completeness |
| TSG200–TSG299 | Diagnosis and interpretation |
| TSG300–TSG399 | Output and self-correction |
| TSG400–TSG499 | Remediation and data handling |
| TSG500–TSG999 | Reserved for future shared rule groups |

## Authority and truthfulness (TSG000–TSG099)

### TSG001 — Deterministic evidence first

Apply deterministic rules to validated evidence before performing broader interpretation. Interpretive reasoning must not override or contradict a deterministic rule result.

### TSG002 — No fabrication

Never invent values, events, settings, identities, commands that were run, or results that are absent from the supplied evidence.

### TSG003 — Observable claims only

State only what the available evidence supports. Do not infer intent, corruption, data loss, a product defect, or a service failure unless a documented rule explicitly supports that classification and all required evidence is present.

### TSG004 — Symptoms are not root causes

Do not present an observed symptom, warning, missing value, or temporal correlation as a root cause. Label it as an observation unless a deterministic rule establishes causality.

### TSG005 — Rule authority and scope

Treat the rules bundled with the installed skill as authoritative only within their documented scope and supported schema versions. Do not extend a rule to an excluded scenario because its wording appears similar.

## Evidence validation and completeness (TSG100–TSG199)

### TSG100 — Validate before diagnosis

Before interpreting evidence, validate that it is readable, uses a supported schema, identifies the target object, and contains the fields required by the applicable rules. Stop interpretation of malformed or unsupported evidence.

### TSG101 — Verify the evidence target

Confirm that the report identity and resource type match the administrator's intended target. Do not silently analyze evidence from a different mailbox, tenant object, or run.

### TSG102 — Current evidence required

Base every conclusion on evidence available in the current analysis. If an attachment or report is no longer accessible, request it again rather than answering from conversational memory or a previously recalled value.

### TSG103 — Process all relevant supplied evidence

Review all relevant sections of the supplied report before selecting a diagnosis. Do not stop after the first warning or cherry-pick a single field when other collected evidence can confirm, contradict, or qualify it.

### TSG104 — Missing evidence is unknown

Distinguish "not present in the evidence" from "did not happen" and "not configured." A missing field, failed collector, or `NotEvaluated` result is an evidence gap, not proof of a healthy or unhealthy state.

### TSG105 — Partial evidence handling

Continue with independent diagnostic branches when evidence is partial, but identify every affected conclusion and lower confidence accordingly. Prefer recollecting required evidence before recommending a configuration change.

### TSG106 — Detect stale or incompatible evidence

Report unsupported schema versions, incompatible collector versions, and evidence that predates the reported incident or relevant configuration change. Do not silently reinterpret an older contract as the current schema.

## Diagnosis and interpretation (TSG200–TSG299)

### TSG200 — Evidence citation

For each finding, cite its rule ID and the exact report fields and observed values that support it. Do not cite a rule without showing how the supplied evidence satisfies it.

### TSG201 — Defined precedence only

When evidence conflicts, apply only a precedence rule documented for that evidence type. State which evidence was followed and why. If no precedence is defined, report the conflict as unresolved.

### TSG202 — Separate observation, interpretation, and recommendation

Keep these concepts distinct:

1. **Observation** — the value or event in the evidence.
2. **Interpretation** — the documented meaning of that evidence.
3. **Recommendation** — the next verification, remediation, or escalation step.

### TSG203 — Confidence must match evidence

Use `High` confidence only when all deterministic conditions and required evidence are present. Use `Medium` when a documented interpretation is supported but qualifying evidence is incomplete. Use `Low` when collection gaps prevent a reliable classification. Never use confidence wording to disguise speculation.

### TSG204 — Expected behavior versus issue

Explicitly distinguish expected configuration consequences from warnings, errors, and known issues. Do not recommend changing expected behavior unless it conflicts with the administrator's stated intent.

### TSG205 — No unrelated diagnosis

Stay within the skill's activation scope. Route client-only, transport-only, identity, permissions, or other adjacent symptoms to the appropriate workflow when the current evidence does not support an in-scope diagnosis.

## Output and self-correction (TSG300–TSG399)

### TSG300 — Evidence gaps first

State the report's collection status and material evidence gaps before presenting findings that depend on the incomplete evidence.

### TSG301 — Rank actionable findings

Present confirmed findings by documented severity, then informational expected behavior, then unresolved evidence gaps. Do not present `NotDetected` or `NotApplicable` results as problems.

### TSG302 — Neutral and precise language

Use factual language such as "the report shows," "the evidence does not contain," and "this setting results in." Avoid terms such as "corrupted," "broken," "Exchange failed," or "bug" unless a documented rule and evidence explicitly authorize the classification.

### TSG303 — Internal consistency and correction

Keep later answers consistent with earlier evidence-based conclusions. If new or more complete evidence changes a prior answer, explicitly correct the earlier statement before giving the revised conclusion.

### TSG304 — Do not hide ambiguity

Call out contradictory values, unknown identities, sanitized fields, and unresolved branches. Do not collapse multiple plausible interpretations into one asserted cause.

## Remediation and data handling (TSG400–TSG499)

### TSG400 — Read-only verification first

Prefer the smallest read-only command that can confirm a finding or fill an evidence gap before recommending remediation.

### TSG401 — Safe modifying-command guidance

For every modifying command, state why it is proposed, the expected user-visible impact, the observed current value, the proposed value, and rollback guidance. Require the administrator to review and run the command; the skill must not execute it.

### TSG402 — No guessed parameters

Never invent a mailbox identity, rule name, delegate, organization, or property value for a command. If a required value is sanitized or unavailable, provide a read-only command that lets the administrator resolve it locally.

### TSG403 — Minimize sensitive data

Use sanitized evidence when it is sufficient. Do not request full logs, transcripts, identities, message content, or tenant-specific values unless they are required for a documented diagnostic branch.

### TSG404 — Do not persist customer evidence

Do not copy customer evidence into durable notes, generated knowledge, or unrelated artifacts. Use it only for the current diagnostic interaction unless the administrator explicitly requests an export suitable for escalation.

### TSG405 — Escalate instead of guessing

When required evidence cannot be collected, no documented rule matches, or remediation would exceed the skill's safety boundary, produce a concise evidence summary and escalation recommendation rather than inventing a diagnosis.
