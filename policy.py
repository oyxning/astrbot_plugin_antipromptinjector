"""Shared runtime and dry-run policy. No I/O, model calls, or state changes."""

from collections.abc import Mapping
from math import isfinite


MODES = ("sentry", "aegis", "scorch", "intercept")
REVIEW_MODES = ("active", "standby", "disabled")


def decide(
    analysis: Mapping,
    config: Mapping,
    *,
    is_private: bool = False,
    observing: bool = False,
    hard_block: str | None = None,
    exempt: bool = False,
    review: Mapping | None = None,
    replacement_available: bool = False,
) -> dict:
    """Choose an action. A pending review must be resolved before acting.

    Review adapter inputs: safe/confirmed with a validated numeric confidence,
    or failed/unavailable. Only a verified whole-request replacement qualifies
    for replacement_available. hard_block is a trusted host/manual restriction.
    """
    mode = config.get("defense_mode", "sentry")
    if mode not in MODES:
        mode = "sentry"
    review_mode = config.get("llm_analysis_mode", "standby")
    if review_mode not in REVIEW_MODES:
        review_mode = "standby"
    suspicious = analysis.get("suspicious") is True
    complete = analysis.get("complete") is True
    needs_attention = suspicious or not complete
    strict = config.get("review_failure_policy") == "strict"
    status = "not_requested"
    request_review = False
    fault = None

    def result(action: str, reason: str) -> dict:
        observe = observing and not hard_block
        punish = (
            not observe and not hard_block and complete and status == "confirmed"
            and mode in ("intercept", "scorch") and action in ("block", "replace")
            and config.get("auto_blacklist") is True
        )
        return {
            "mode": mode,
            "action": "allow" if observe else action,
            "would_action": action,
            "reason": reason,
            "observing": observe,
            "review_required": request_review,
            "review_status": status,
            "fault": fault,
            "auto_ban": bool(punish),
            "suspicious": suspicious,
            "complete": complete,
        }

    if hard_block:
        return result("block", hard_block)
    if config.get("enabled", True) is False:
        return result("allow", "disabled")
    if exempt:
        return result("allow", "exempt")
    if mode == "sentry":
        if needs_attention:
            return result("harden", "rule_evidence" if suspicious else "inspection_incomplete")
        return result("allow", "no_evidence")

    private_disabled = is_private and config.get("llm_analysis_private_chat_enabled") is not True
    review_allowed = review_mode != "disabled" and not private_disabled
    mandatory = mode == "aegis" and needs_attention
    should_review = mandatory or (review_allowed and (review_mode == "active" or needs_attention))
    if should_review:
        if not review_allowed:
            status = "unavailable"
            fault = "private_review_disabled" if private_disabled else "review_disabled"
        elif review is None:
            request_review = True
            status = "pending"
            return result("block" if needs_attention or strict else "allow", "review_pending")
        elif not isinstance(review, Mapping):
            status = "failed"
            fault = "invalid_review"
        else:
            status = review.get("status")
            confidence = review.get("confidence")
            if status in ("safe", "confirmed"):
                if (type(confidence) not in (int, float)
                        or not 0 <= confidence <= 1 or not isfinite(confidence)):
                    status = "failed"
                    fault = "invalid_review"
            elif status in ("failed", "unavailable"):
                fault = review.get("fault") or "review_unavailable"
            else:
                status = "failed"
                fault = "invalid_review"
        if status in ("failed", "unavailable"):
            return result("block" if needs_attention or strict else "allow", "review_failure")
        if status == "safe" and complete:
            return result("allow", "review_safe")

    if not complete:
        return result("block", "inspection_incomplete")
    if not suspicious and status != "confirmed":
        return result("allow", "no_evidence")
    reason = "review_confirmed" if status == "confirmed" else "rule_evidence"
    if mode == "aegis":
        return result("harden", reason)
    if mode == "scorch" and replacement_available:
        return result("replace", reason)
    if mode == "scorch":
        return result("block", "replacement_unavailable")
    return result("block", reason)
