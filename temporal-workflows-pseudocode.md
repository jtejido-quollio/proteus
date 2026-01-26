# Temporal workflow pseudocode (Phase 4B)

## Workflow: CaseLifecycleWorkflow (pseudocode)

**Signals**
- Assign(ownerId)
- AddEvidence(evidenceRef)
- PlaceHold(holdSpec)
- ReleaseHold(holdId, rationale)
- Escalate(target, rationale)
- Override(overrideSpec)
- AddHumanAction(action)
- Resolve(resolutionSpec)
- Close(closeSpec)

**Queries**
- State()
- SLA()
- ActiveHolds()
- Assignee()

**Activities (examples)**
- CreateCase, AppendCaseEvent, EnsureQueueItem, UpdateQueueState
- ComputeCaseSLA, EvaluateEscalationPolicy, Notify
- SnapshotPolicyBundle, LinkEvidence, RecordHold, RecordOverride, PersistResolution

```text
workflow CaseLifecycleWorkflow(input):
  state := initState()

  CreateCase(input)
  AppendCaseEvent(CASE_OPENED)

  sla := ComputeCaseSLA(type, severity)
  EnsureQueueItem(caseId, queueId, sla.deadline)
  timer := NewTimer(sla.deadline - now)

  loop:
    select:
      on timer:
        AppendCaseEvent(SLA_BREACHED)
        decision := EvaluateEscalationPolicy(caseId, state)
        if decision.shouldEscalate:
           AppendCaseEvent(ESCALATED)
           Notify(decision.target)
        timer = NewTimer(nextEscalationDeadline(state))

      on SignalAssign(ownerId):
        AppendCaseEvent(ASSIGNED)
        UpdateQueueState(IN_REVIEW)

      on SignalPlaceHold(holdSpec):
        holdId := RecordHold(holdSpec)
        AppendCaseEvent(HOLD_PLACED)

      on SignalOverride(overrideSpec):
        snap := SnapshotPolicyBundle(overrideSpec.policyBundleRef)
        overrideSpec.policySnapshotRef = snap
        RecordOverride(overrideSpec)
        AppendCaseEvent(OVERRIDE_RECORDED)

      on SignalResolve(resolutionSpec):
        PersistResolution(resolutionSpec)
        AppendCaseEvent(RESOLVED)
        UpdateQueueState(RESOLVED)

      on SignalClose(closeSpec):
        AppendCaseEvent(CLOSED)
        UpdateQueueState(CLOSED)
        break
```

## Workflow: EvidencePackExportWorkflow (pseudocode)

```text
workflow EvidencePackExportWorkflow(input):
  AuthorizeExport(input)
  EmitAudit(EXPORT_REQUESTED)

  if requiresApproval:
     wait for ApproveExport signal

  refs := GatherEvidenceRefs(caseId, include)
  manifest := BuildPackManifest(caseId, refs)
  Write("manifest.json", manifest)

  for ref in refs:
     blob := FetchBlob(ref)
     Write(ref.packPath, blob)

  sigs := ComputePackHashes()
  if signingEnabled:
     sigs := SignPack(sigs)
  Write("signatures.json", sigs)

  exportId := PersistExportRecord(...)
  storageRef := StorePack(...)
  EmitAudit(EXPORT_COMPLETED)
  return {exportId, storageRef}
```

## Can the workflow service be a wrapper around Temporal?
Yes:
- Services call **typed stubs** (start/signal/query).
- Temporal owns timers/retries/long-running orchestration.
- Your DB remains the source-of-truth for append-only case events and evidence references.
