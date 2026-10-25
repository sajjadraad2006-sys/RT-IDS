"""Central router and dispatcher for defensive actuators.

Coordinates formal SMT safety gate validation, actuator selection,
operational mode enforcement (simulation vs enforcement),
cryptographic HMAC-SHA256 receipt tracking, and atomic rollback dispatch.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

from .base import ActuatorResult
from .firewall import FirewallActuator
from .guardrails import SafetyGuardrails
from .process import ProcessActuator
from .suricata_rules import SuricataActuator
from ..safety.formal_verifier import (
    FormalSafetyVerifier,
    RollbackReceipt,
)

logger = logging.getLogger("cyberguard.actuators.router")


class ActuatorRouter:
    """Dispatches defensive actions to the appropriate actuator under formal safety constraints."""

    def __init__(
        self,
        guardrails: Optional[SafetyGuardrails] = None,
        firewall: Optional[FirewallActuator] = None,
        suricata: Optional[SuricataActuator] = None,
        process: Optional[ProcessActuator] = None,
        safety_verifier: Optional[FormalSafetyVerifier] = None,
        require_two_person: Optional[bool] = None,
    ):
        self.guardrails = guardrails or SafetyGuardrails()
        self.firewall = firewall or FirewallActuator()
        self.suricata = suricata or SuricataActuator()
        self.process = process or ProcessActuator()
        self._safety_verifier = safety_verifier

        if require_two_person is None:
            env_two_person = os.getenv("CG_REQUIRE_TWO_PERSON") or os.getenv("CG_REQUIRE_TWO_PERSON_RULE", "true")
            self.require_two_person = env_two_person.lower() in ("true", "1", "yes")
        else:
            self.require_two_person = bool(require_two_person)
        self._lock = threading.Lock()
        self._active_blocks: Dict[str, ActuatorResult] = {}
        self._receipt_map: Dict[str, Dict[str, Any]] = {}

    @property
    def safety_verifier(self) -> FormalSafetyVerifier:
        if self._safety_verifier is None:
            from ..safety.formal_verifier import default_safety_verifier
            self._safety_verifier = default_safety_verifier
        return self._safety_verifier

    @safety_verifier.setter
    def safety_verifier(self, val: FormalSafetyVerifier) -> None:
        self._safety_verifier = val

    def execute_action(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None,
        mode: str = "simulation",
        proof_receipt: Optional[RollbackReceipt] = None,
    ) -> ActuatorResult:
        """Validate formal invariants and execute action across appropriate actuator.

        Args:
            action: e.g. "block_ip", "isolate_port", "kill_process", "drop_suricata_signature"
            target: IP, Port, Process Name, or signature identifier
            params: Optional extra parameters (e.g. port, protocol, sid)
            mode: "simulation" (dry-run) or "enforcement" (live action)
            proof_receipt: Optional pre-signed RollbackReceipt from FormalSafetyVerifier
        """
        params = params or {}
        dry_run = (mode.lower() != "enforcement")

        # 0. Two-Person Rule authorization check for live containment enforcement
        if not dry_run and self.require_two_person:
            initiator = str(params.get("initiator_id") or "").strip()
            approver = str(params.get("approver_id") or "").strip()
            if not initiator or not approver:
                logger.warning(
                    "Two-Person Rule blocked enforcement action '%s' on '%s': missing initiator or approver",
                    action,
                    target,
                )
                return ActuatorResult(
                    success=False,
                    action=action,
                    target=target,
                    command_executed="",
                    output="",
                    simulated=False,
                    error="Two-Person Rule violation: Dual authorization required (initiator_id and approver_id must be provided for live containment)",
                    metadata={"two_person_rule_violated": True, "initiator_id": initiator, "approver_id": approver},
                )
            if initiator.lower() == approver.lower():
                logger.warning(
                    "Two-Person Rule blocked enforcement action '%s' on '%s': initiator '%s' cannot self-approve",
                    action,
                    target,
                    initiator,
                )
                return ActuatorResult(
                    success=False,
                    action=action,
                    target=target,
                    command_executed="",
                    output="",
                    simulated=False,
                    error=f"Two-Person Rule violation: Initiator '{initiator}' cannot self-approve their own live containment action (distinct approver required)",
                    metadata={"two_person_rule_violated": True, "initiator_id": initiator, "approver_id": approver},
                )

        # 1. Formal Neuro-Symbolic Safety Gate Evaluation (Invariants I_1 to I_4)
        active_receipt = proof_receipt
        if active_receipt is not None:
            # Verify cryptographic signature of the supplied proof receipt
            if not self.safety_verifier.verify_receipt(active_receipt):
                logger.error("Supplied rollback receipt signature invalid/tampered: %s", active_receipt.token)
                return ActuatorResult(
                    success=False,
                    action=action,
                    target=target,
                    command_executed="",
                    output="",
                    simulated=dry_run,
                    error="Cryptographic rollback receipt verification failed (tampered token)",
                    metadata={"tampered_token": True},
                )
        else:
            # Perform formal verification pass and generate signed receipt
            v_res = self.safety_verifier.verify_and_sign(
                action=action,
                target=target,
                severity=str(params.get("severity", "high")),
                confidence=float(params.get("confidence", 0.90)),
                parameters=params,
            )
            if not v_res.admitted:
                violations_str = ", ".join(v.value for v in v_res.violated_invariants)
                logger.warning(
                    "Formal safety verifier blocked action '%s' on '%s': %s",
                    action,
                    target,
                    violations_str,
                )
                return ActuatorResult(
                    success=False,
                    action=action,
                    target=target,
                    command_executed="",
                    output="",
                    simulated=dry_run,
                    error=f"Guardrail violation: Formal safety gate violation ({violations_str})",
                    metadata={"violated_invariants": [v.value for v in v_res.violated_invariants]},
                )
            active_receipt = v_res.rollback_receipt

        # 2. Legacy guardrail validation
        is_safe, reason = self.guardrails.validate_action(action, target, params)
        if not is_safe:
            logger.warning("Guardrail blocked action '%s' on '%s': %s", action, target, reason)
            return ActuatorResult(
                success=False,
                action=action,
                target=target,
                command_executed="",
                output="",
                simulated=dry_run,
                error=f"Guardrail violation: {reason}",
                metadata={"guardrail_violated": True, "reason": reason},
            )

        # 3. Route to corresponding actuator
        actuator_type = "unknown"
        if action in {"block_ip", "isolate_port", "rate_limit", "isolate_host"}:
            actuator_type = "firewall"
            result = self.firewall.execute(action, target, params, dry_run=dry_run)
        elif action in {"drop_suricata_signature", "suricata_drop"}:
            actuator_type = "suricata"
            result = self.suricata.execute(action, target, params, dry_run=dry_run)
        elif action in {"kill_process", "suspend_process"}:
            actuator_type = "process"
            result = self.process.execute(action, target, params, dry_run=dry_run)
        else:
            return ActuatorResult(
                success=False,
                action=action,
                target=target,
                command_executed="",
                output="",
                simulated=dry_run,
                error=f"No suitable actuator found for action '{action}'",
            )

        # 4. Bind cryptographic HMAC rollback receipt if execution succeeded
        if result.success and active_receipt:
            underlying_token = result.rollback_token or ""
            proof_token = active_receipt.token

            with self._lock:
                # Prefer cryptographic proof token as primary rollback identifier
                result.rollback_token = proof_token
                self._active_blocks[proof_token] = result
                if underlying_token:
                    self._active_blocks[underlying_token] = result

                self._receipt_map[proof_token] = {
                    "receipt": active_receipt,
                    "underlying_token": underlying_token,
                    "actuator_type": actuator_type,
                    "action": action,
                    "target": target,
                }

                # Persist to SQLite for cross-process rollback durability across restarts
                try:
                    import json
                    from ..db.models import ActionReceiptRecord, SessionLocal
                    ttl_sec = int(params.get("ttl_seconds", 0) or 0)
                    expires_at = (time.time() + ttl_sec) if ttl_sec > 0 else None
                    rollback_cmd = result.metadata.get("rollback_cmd", "") if isinstance(result.metadata, dict) else ""

                    with SessionLocal() as db_session:
                        rec = ActionReceiptRecord(
                            token=proof_token,
                            underlying_token=underlying_token,
                            actuator_type=actuator_type,
                            action=action,
                            target=target,
                            params_json=json.dumps(params),
                            receipt_json=json.dumps({
                                "token": active_receipt.token,
                                "action_type": active_receipt.action_type,
                                "target": active_receipt.target,
                                "parameters_json": active_receipt.parameters_json,
                                "timestamp": active_receipt.timestamp,
                                "signature_hmac": active_receipt.signature_hmac,
                                "state_inversion_digest": active_receipt.state_inversion_digest,
                            }),
                            status="active",
                            is_simulated=bool(result.simulated),
                            ttl_seconds=ttl_sec if ttl_sec > 0 else None,
                            expires_at=expires_at,
                            executed_command=str(result.command_executed or ""),
                            rollback_command=str(rollback_cmd or ""),
                        )
                        db_session.add(rec)
                        db_session.commit()
                except Exception as db_err:
                    logger.debug("Could not persist rollback receipt to DB: %s", db_err)

            if not dry_run:
                self.guardrails.record_execution()

        return result

    def rollback_action(self, rollback_token: str) -> bool:
        """Roll back an action by its cryptographic proof token or actuator token.

        Guarantees Invariant I_3 (Atomic Invertibility) across process restarts.
        """
        with self._lock:
            # 1. Cryptographic HMAC Proof Token Rollback
            if rollback_token.startswith("cg-proof-") or rollback_token.startswith("cg-fw-"):
                mapping = self._receipt_map.get(rollback_token)
                db_record_id = None
                if not mapping:
                    # Query persistent database storage across process restarts
                    try:
                        import json
                        from ..db.models import ActionReceiptRecord, SessionLocal
                        with SessionLocal() as db_session:
                            rec = db_session.query(ActionReceiptRecord).filter(
                                (ActionReceiptRecord.token == rollback_token) |
                                (ActionReceiptRecord.underlying_token == rollback_token)
                            ).first()
                            if rec and rec.status == "active":
                                rec_data = json.loads(rec.receipt_json)
                                reconstructed_receipt = RollbackReceipt(
                                    token=rec_data["token"],
                                    action_type=rec_data["action_type"],
                                    target=rec_data["target"],
                                    parameters_json=rec_data["parameters_json"],
                                    timestamp=float(rec_data["timestamp"]),
                                    signature_hmac=rec_data["signature_hmac"],
                                    state_inversion_digest=rec_data["state_inversion_digest"],
                                )
                                mapping = {
                                    "receipt": reconstructed_receipt,
                                    "underlying_token": rec.underlying_token,
                                    "actuator_type": rec.actuator_type,
                                    "action": rec.action,
                                    "target": rec.target,
                                }
                                db_record_id = rec.id
                    except Exception as db_lookup_err:
                        logger.debug("Database receipt lookup failed: %s", db_lookup_err)

                if not mapping:
                    logger.warning("Proof rollback token %s not found in memory or persistent store", rollback_token)
                    return False

                receipt: RollbackReceipt = mapping["receipt"]
                if not self.safety_verifier.verify_receipt(receipt):
                    logger.error("Tampered rollback token signature detected: %s", rollback_token)
                    return False

                underlying_token = mapping["underlying_token"]
                actuator_type = mapping["actuator_type"]
                rolled_back = False

                if actuator_type == "firewall":
                    rolled_back = self.firewall.rollback(underlying_token)
                elif actuator_type == "suricata":
                    rolled_back = self.suricata.rollback(underlying_token)
                elif actuator_type == "process":
                    rolled_back = self.process.rollback(underlying_token)

                if rolled_back:
                    self._active_blocks.pop(rollback_token, None)
                    if underlying_token:
                        self._active_blocks.pop(underlying_token, None)
                    self._receipt_map.pop(rollback_token, None)
                    try:
                        import time
                        from ..db.models import ActionReceiptRecord, SessionLocal
                        with SessionLocal() as db_session:
                            d_rec = None
                            if db_record_id:
                                d_rec = db_session.get(ActionReceiptRecord, db_record_id)
                            if not d_rec:
                                d_rec = db_session.query(ActionReceiptRecord).filter(
                                    (ActionReceiptRecord.token == rollback_token) |
                                    (ActionReceiptRecord.underlying_token == rollback_token)
                                ).first()
                            if d_rec:
                                d_rec.status = "rolled_back"
                                d_rec.rolled_back_at = time.time()
                                db_session.commit()
                    except Exception as db_err:
                        logger.debug("Failed updating ActionReceiptRecord to rolled_back: %s", db_err)
                    logger.info("Successfully executed atomic state rollback for token %s", rollback_token)
                return rolled_back

            # 2. Direct Actuator Token Rollback (cg-fw-, cg-suri-, cg-proc-)
            result = self._active_blocks.get(rollback_token)
            if not result:
                logger.warning("Rollback token %s not found in router registry", rollback_token)
                return False

            rolled_back = False
            if rollback_token.startswith("cg-fw-"):
                rolled_back = self.firewall.rollback(rollback_token)
            elif rollback_token.startswith("cg-suri-"):
                rolled_back = self.suricata.rollback(rollback_token)
            elif rollback_token.startswith("cg-proc-"):
                rolled_back = self.process.rollback(rollback_token)

            if rolled_back:
                self._active_blocks.pop(rollback_token, None)
                # Clean up any paired proof token
                paired_proof = next(
                    (p_tok for p_tok, data in self._receipt_map.items() if data.get("underlying_token") == rollback_token),
                    None,
                )
                if paired_proof:
                    self._active_blocks.pop(paired_proof, None)
                    self._receipt_map.pop(paired_proof, None)
                logger.info("Successfully rolled back actuator action with token %s", rollback_token)

            return rolled_back

    def list_active_blocks(self) -> List[Dict[str, Any]]:
        """Return all tracked active or simulated mitigations without duplicates."""
        with self._lock:
            # Return distinct results
            seen = set()
            unique_results = []
            for res in self._active_blocks.values():
                tok = res.rollback_token or ""
                if tok and tok not in seen:
                    seen.add(tok)
                    unique_results.append(res.model_dump(mode="json"))
            return unique_results

    def clear_all(self) -> None:
        """Reset router state (primarily for isolated test fixtures)."""
        with self._lock:
            self._active_blocks.clear()
            self._receipt_map.clear()

    def sweep_expired_actions(self) -> int:
        """Scan active containment actions whose TTL has expired and execute atomic rollback."""
        now = time.time()
        expired_tokens: List[str] = []
        try:
            from ..db.models import ActionReceiptRecord, SessionLocal
            with SessionLocal() as db_session:
                records = db_session.query(ActionReceiptRecord).filter(
                    ActionReceiptRecord.status == "active",
                    ActionReceiptRecord.expires_at.isnot(None),
                    ActionReceiptRecord.expires_at <= now,
                ).all()
                for rec in records:
                    expired_tokens.append(rec.token)
        except Exception as exc:
            logger.debug("Error querying expired actions: %s", exc)
            return 0

        rolled_back_count = 0
        for tok in expired_tokens:
            try:
                logger.info("Executing automated TTL expiration rollback for action receipt: %s", tok)
                if self.rollback_action(tok):
                    rolled_back_count += 1
            except Exception as exc:
                logger.error("Failed executing automated TTL expiration rollback for %s: %s", tok, exc)

        return rolled_back_count

    def start_ttl_reaper(self, interval_sec: float = 10.0) -> None:
        """Start background daemon thread periodically sweeping expired containment actions."""
        if hasattr(self, "_reaper_thread") and self._reaper_thread and self._reaper_thread.is_alive():
            return

        self._reaper_running = True
        def _reaper_loop():
            while self._reaper_running:
                try:
                    self.sweep_expired_actions()
                except Exception as e:
                    logger.debug("TTL reaper error: %s", e)
                time.sleep(interval_sec)

        self._reaper_thread = threading.Thread(target=_reaper_loop, daemon=True, name="cyberguard-ttl-reaper")
        self._reaper_thread.start()
        logger.info("Containment TTL background reaper started (interval=%ss).", interval_sec)

    def stop_ttl_reaper(self) -> None:
        self._reaper_running = False


# Global singleton instance
default_router = ActuatorRouter()
