package proteus.policy

default allow = false

deny_codes["SIGNATURE_INVALID"] {
	not input.verification.signature_valid
}

deny_codes["KEY_REVOKED"] {
	input.verification.key_status == "revoked"
}

deny_codes["LOG_PROOF_INVALID"] {
	not input.verification.log_included
}

deny_codes["PROOF_REQUIRED"] {
	input.options.require_proof
	not input.verification.log_included
}

allow {
	count(deny_codes) == 0
}

result := {
	"allow": allow,
	"deny": [ {"code": c} | c := sort(deny_codes)[_] ],
}
