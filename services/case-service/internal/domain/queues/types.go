package queues

type SLAState string

const (
	SLAStateActive   SLAState = "active"
	SLAStatePaused   SLAState = "paused"
	SLAStateBreached SLAState = "breached"
)
