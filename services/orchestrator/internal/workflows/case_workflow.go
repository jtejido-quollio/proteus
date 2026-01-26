package workflows

import (
	"fmt"
	"time"

	"proteus/orchestrator/internal/activities"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

type caseState struct {
	workflowID  string
	slaDeadline time.Time
	reminderAt  time.Time
	onHold      bool
	pausedAt    time.Time
	seq         int
	processed   map[string]struct{}
	reminderSet bool
}

func CaseWorkflow(ctx workflow.Context, input CaseWorkflowInput) error {
	info := workflow.GetInfo(ctx)
	state := &caseState{
		workflowID: info.WorkflowExecution.ID,
		processed:  make(map[string]struct{}),
	}
	logger := workflow.GetLogger(ctx)

	sla := normalizeSLA(input.SLA)
	now := workflow.Now(ctx)
	state.slaDeadline = now.Add(sla.BreachAfter)
	if sla.ReminderLead > 0 {
		state.reminderAt = state.slaDeadline.Add(-sla.ReminderLead)
		state.reminderSet = state.reminderAt.After(now)
	}

	activityOpts := workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    1 * time.Second,
			BackoffCoefficient: 2.0,
			MaximumInterval:    30 * time.Second,
			MaximumAttempts:    5,
		},
	}
	ctx = workflow.WithActivityOptions(ctx, activityOpts)

	assignCh := workflow.GetSignalChannel(ctx, SignalAssign)
	holdCh := workflow.GetSignalChannel(ctx, SignalHold)
	unholdCh := workflow.GetSignalChannel(ctx, SignalUnhold)
	escalateCh := workflow.GetSignalChannel(ctx, SignalEscalate)
	resolveCh := workflow.GetSignalChannel(ctx, SignalResolve)
	commentCh := workflow.GetSignalChannel(ctx, SignalComment)

	timers := newTimerState(ctx, state)
	defer timers.stop()

	if err := workflow.SetQueryHandler(ctx, "state", func() (caseState, error) {
		return *state, nil
	}); err != nil {
		return err
	}
	if err := workflow.SetQueryHandler(ctx, "sla", func() (time.Time, error) {
		return state.slaDeadline, nil
	}); err != nil {
		return err
	}
	if err := workflow.SetQueryHandler(ctx, "holds", func() (bool, error) {
		return state.onHold, nil
	}); err != nil {
		return err
	}

	done := false
	for !done {
		selector := workflow.NewSelector(ctx)

		if timers.reminderFuture != nil {
			selector.AddFuture(timers.reminderFuture, func(f workflow.Future) {
				_ = f.Get(ctx, nil)
				if state.onHold {
					return
				}
				requestID := state.nextSystemRequestID(EventSLARemind)
				err := emitEvent(ctx, input, EventSLARemind, requestID, map[string]any{
					"sla_deadline": state.slaDeadline.UTC().Format(time.RFC3339Nano),
				})
				if err != nil {
					logger.Error("emit reminder event failed", "error", err)
				}
				timers.reminderFuture = nil
				state.reminderSet = false
			})
		}

		if timers.breachFuture != nil {
			selector.AddFuture(timers.breachFuture, func(f workflow.Future) {
				_ = f.Get(ctx, nil)
				if state.onHold {
					return
				}
				requestID := state.nextSystemRequestID(EventSLABreach)
				err := emitEvent(ctx, input, EventSLABreach, requestID, map[string]any{
					"sla_deadline": state.slaDeadline.UTC().Format(time.RFC3339Nano),
				})
				if err != nil {
					logger.Error("emit sla breached event failed", "error", err)
				}
				notifyErr := workflow.ExecuteActivity(ctx, activities.NotifyActivityName, activities.NotifyInput{
					TenantID: input.TenantID,
					CaseID:   input.CaseID,
					Message:  "SLA breached",
				}).Get(ctx, nil)
				if notifyErr != nil {
					logger.Error("notify activity failed", "error", notifyErr)
				}
				timers.breachFuture = nil
			})
		}

		selector.AddReceive(assignCh, func(c workflow.ReceiveChannel, more bool) {
			var sig AssignSignal
			c.Receive(ctx, &sig)
			if state.isDuplicate(sig.RequestID) {
				return
			}
			payload := map[string]any{
				"assignee_id": sig.OwnerID,
			}
			if err := emitEvent(ctx, input, EventAssigned, sig.RequestID, payload); err != nil {
				logger.Error("emit assigned event failed", "error", err)
			}
		})

		selector.AddReceive(holdCh, func(c workflow.ReceiveChannel, more bool) {
			var sig HoldSignal
			c.Receive(ctx, &sig)
			if state.isDuplicate(sig.RequestID) {
				return
			}
			if !state.onHold {
				state.onHold = true
				state.pausedAt = workflow.Now(ctx)
				timers.stop()
			}
			payload := map[string]any{
				"hold_type": sig.HoldType,
				"reason":    sig.Reason,
			}
			if err := emitEvent(ctx, input, EventHoldPlaced, sig.RequestID, payload); err != nil {
				logger.Error("emit hold event failed", "error", err)
			}
		})

		selector.AddReceive(unholdCh, func(c workflow.ReceiveChannel, more bool) {
			var sig UnholdSignal
			c.Receive(ctx, &sig)
			if state.isDuplicate(sig.RequestID) {
				return
			}
			if state.onHold {
				pausedFor := workflow.Now(ctx).Sub(state.pausedAt)
				state.slaDeadline = state.slaDeadline.Add(pausedFor)
				if state.reminderSet {
					state.reminderAt = state.reminderAt.Add(pausedFor)
				}
				state.onHold = false
				timers.reset(ctx, state)
			}
			payload := map[string]any{
				"reason": sig.Reason,
			}
			if err := emitEvent(ctx, input, EventHoldGone, sig.RequestID, payload); err != nil {
				logger.Error("emit unhold event failed", "error", err)
			}
		})

		selector.AddReceive(escalateCh, func(c workflow.ReceiveChannel, more bool) {
			var sig EscalateSignal
			c.Receive(ctx, &sig)
			if state.isDuplicate(sig.RequestID) {
				return
			}
			payload := map[string]any{
				"from_queue_id": sig.FromQueueID,
				"to_queue_id":   sig.ToQueueID,
				"reason":        sig.Reason,
			}
			if err := emitEvent(ctx, input, EventEscalated, sig.RequestID, payload); err != nil {
				logger.Error("emit escalation event failed", "error", err)
			}
		})

		selector.AddReceive(resolveCh, func(c workflow.ReceiveChannel, more bool) {
			var sig ResolveSignal
			c.Receive(ctx, &sig)
			if state.isDuplicate(sig.RequestID) {
				return
			}
			payload := map[string]any{
				"resolution": sig.Resolution,
			}
			if err := emitEvent(ctx, input, EventResolved, sig.RequestID, payload); err != nil {
				logger.Error("emit resolved event failed", "error", err)
			}
			timers.stop()
			done = true
		})

		selector.AddReceive(commentCh, func(c workflow.ReceiveChannel, more bool) {
			var sig CommentSignal
			c.Receive(ctx, &sig)
			if state.isDuplicate(sig.RequestID) {
				return
			}
			payload := map[string]any{
				"body": sig.Body,
			}
			if err := emitEvent(ctx, input, EventCommented, sig.RequestID, payload); err != nil {
				logger.Error("emit comment event failed", "error", err)
			}
		})

		selector.Select(ctx)
	}
	return nil
}

type timerState struct {
	cancelFunc     workflow.CancelFunc
	breachFuture   workflow.Future
	reminderFuture workflow.Future
}

func newTimerState(ctx workflow.Context, state *caseState) *timerState {
	ts := &timerState{}
	ts.reset(ctx, state)
	return ts
}

func (t *timerState) reset(ctx workflow.Context, state *caseState) {
	if t.cancelFunc != nil {
		t.cancelFunc()
	}
	timerCtx, cancel := workflow.WithCancel(ctx)
	t.cancelFunc = cancel

	now := workflow.Now(ctx)
	breachDelay := state.slaDeadline.Sub(now)
	if breachDelay < 0 {
		breachDelay = 0
	}
	t.breachFuture = workflow.NewTimer(timerCtx, breachDelay)

	if state.reminderSet {
		reminderDelay := state.reminderAt.Sub(now)
		if reminderDelay > 0 {
			t.reminderFuture = workflow.NewTimer(timerCtx, reminderDelay)
			return
		}
	}
	t.reminderFuture = nil
}

func (t *timerState) stop() {
	if t.cancelFunc != nil {
		t.cancelFunc()
	}
}

func (s *caseState) isDuplicate(requestID string) bool {
	if requestID == "" {
		return false
	}
	if _, ok := s.processed[requestID]; ok {
		return true
	}
	s.processed[requestID] = struct{}{}
	return false
}

func (s *caseState) nextSystemRequestID(eventType string) string {
	s.seq++
	return fmt.Sprintf("%s:%s:%d", s.workflowID, eventType, s.seq)
}

func normalizeSLA(input SLAConfig) SLAConfig {
	if input.BreachAfter <= 0 {
		input.BreachAfter = 24 * time.Hour
	}
	if input.ReminderLead < 0 {
		input.ReminderLead = 0
	}
	return input
}

func emitEvent(ctx workflow.Context, input CaseWorkflowInput, eventType, requestID string, payload map[string]any) error {
	return workflow.ExecuteActivity(ctx, activities.EmitCaseEventActivityName, activities.EmitCaseEventInput{
		TenantID:  input.TenantID,
		CaseID:    input.CaseID,
		EventType: eventType,
		RequestID: requestID,
		Payload:   payload,
	}).Get(ctx, nil)
}
