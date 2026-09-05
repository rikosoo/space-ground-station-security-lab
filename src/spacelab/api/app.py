"""Mission-control API: authentication, RBAC and telecommand submission.

This is the internet-facing edge of the ground segment and therefore the entry
point for attacks A1 (credential compromise) and A2 (unauthorized command). The
class is transport-agnostic on purpose: ``serve.py`` wraps it in FastAPI for the
deployed instantiation, while the experiment harness calls it directly so that
runs are deterministic and can be time-accelerated.

Preventive controls implemented here, each independently switchable so the
ablation study (RQ4) can attribute outcomes to a specific mechanism:

* ``enforce_rbac``       - per-role command allowlist,
* ``enforce_mfa``        - second factor on session establishment,
* ``enforce_rate_limit`` - per-principal command rate limiting,
* ``enforce_pass_window``- refuse commands with no feasible link.
"""

from __future__ import annotations

import hashlib
import random
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional

from ..bus import EventBus
from ..ccsds import SpacePacket
from ..crypto import sign
from ..events import (
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    SRC_API_AUTH,
    SRC_API_COMMAND,
    Event,
)
from ..groundstation.station import GroundStation
from ..satellite.simulator import COMMAND_CATALOG

#: Least-privilege command allowlists. ``flight_director`` is the only role
#: allowed to issue critical commands.
ROLE_PERMISSIONS: Dict[str, set] = {
    "observer": {"PING", "HK_REQUEST"},
    "operator": {"PING", "HK_REQUEST", "TLM_RATE_SET", "PAYLOAD_ON", "PAYLOAD_OFF",
                 "RECORDER_DUMP"},
    "flight_director": set(COMMAND_CATALOG.keys()),
}


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


@dataclass
class Operator:
    user_id: str
    role: str
    password: str
    usual_ip: str
    usual_asn: str = "AS28573-BR"
    mfa_enrolled: bool = True

    @property
    def password_hash(self) -> str:
        return _hash(self.password)


@dataclass
class Session:
    token: str
    user_id: str
    role: str
    src_ip: str
    asn: str
    created_at: float


@dataclass
class MissionControlAPI:
    bus: EventBus
    ground_station: GroundStation
    operators: Dict[str, Operator] = field(default_factory=dict)
    rng: random.Random = field(default_factory=lambda: random.Random(23))

    enforce_rbac: bool = True
    enforce_mfa: bool = True
    enforce_rate_limit: bool = True
    enforce_pass_window: bool = True
    rate_limit_per_min: int = 20

    sessions: Dict[str, Session] = field(default_factory=dict)
    _tc_seq: int = 0
    _recent_cmds: Dict[str, Deque[float]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    blocked_principals: set = field(default_factory=set)

    def add_operator(self, op: Operator) -> None:
        self.operators[op.user_id] = op

    # ------------------------------------------------------------------ auth
    def login(
        self, user_id: str, password: str, src_ip: str, t: float,
        asn: str = "AS28573-BR", user_agent: str = "mcs-console/4.2",
        mfa_presented: bool = True, ground_truth: str = "benign",
    ) -> Optional[str]:
        op = self.operators.get(user_id)
        ok = op is not None and op.password_hash == _hash(password)
        reason = "ok"
        if not ok:
            reason = "bad_credentials"
        elif self.enforce_mfa and op.mfa_enrolled and not mfa_presented:
            ok, reason = False, "mfa_required"
        elif user_id in self.blocked_principals:
            ok, reason = False, "principal_blocked"

        token = None
        if ok:
            token = f"tok-{self.rng.getrandbits(48):012x}"
            self.sessions[token] = Session(token, user_id, op.role, src_ip, asn, t)

        self.bus.publish(
            Event(
                ts=t, source=SRC_API_AUTH, event_type="auth.login",
                actor=user_id, target="mission-control-api",
                outcome=OUTCOME_SUCCESS if ok else OUTCOME_FAILURE, src_ip=src_ip,
                attrs={
                    "reason": reason,
                    "asn": asn,
                    "user_agent": user_agent,
                    "mfa_presented": mfa_presented,
                    "role": op.role if op else "-",
                },
                ground_truth=ground_truth,
            )
        )
        return token

    def hijack_session(
        self, user_id: str, src_ip: str, t: float, asn: str = "-",
        user_agent: str = "python-requests/2.31", ground_truth: str = "benign",
    ) -> Optional[str]:
        """Mint a session from a stolen session token.

        Models adversary-in-the-middle phishing, where the second factor is
        relayed and the resulting session cookie is replayed by the attacker.
        The API cannot distinguish it from a legitimate logon at authentication
        time, which is precisely why the *origin* of the session is the signal.
        """
        op = self.operators.get(user_id)
        if op is None or user_id in self.blocked_principals:
            return None
        token = f"tok-{self.rng.getrandbits(48):012x}"
        self.sessions[token] = Session(token, user_id, op.role, src_ip, asn, t)
        self.bus.publish(
            Event(
                ts=t, source=SRC_API_AUTH, event_type="auth.login",
                actor=user_id, target="mission-control-api",
                outcome=OUTCOME_SUCCESS, src_ip=src_ip,
                attrs={
                    "reason": "ok", "asn": asn, "user_agent": user_agent,
                    "mfa_presented": True, "role": op.role,
                    "auth_method": "session_token_replay",
                },
                ground_truth=ground_truth,
            )
        )
        return token

    # --------------------------------------------------------------- command
    def submit_command(
        self, token: str, command: str, t: float, args: Optional[dict] = None,
        src_ip: Optional[str] = None, ground_truth: str = "benign",
        spoof_tag: bool = False, force_seq: Optional[int] = None,
    ) -> dict:
        """Authorize, sign and uplink one telecommand.

        Args:
            spoof_tag: emit an invalid SDLS tag (used by attack A2 variants that
                bypass the API and inject at the RF layer).
            force_seq: reuse a specific frame counter (used by attack A4).
        """
        args = args or {}
        sess = self.sessions.get(token)
        ip = src_ip or (sess.src_ip if sess else "-")
        spec = COMMAND_CATALOG.get(command)

        def deny(reason: str) -> dict:
            self.bus.publish(
                Event(
                    ts=t, source=SRC_API_COMMAND, event_type="command.submit",
                    actor=sess.user_id if sess else "anonymous",
                    target=self.ground_station.spacecraft.spacecraft_id,
                    outcome=OUTCOME_FAILURE, src_ip=ip,
                    attrs={
                        "command": command, "args": args, "reason": reason,
                        "role": sess.role if sess else "-",
                        "critical": bool(spec and spec["critical"]),
                        "session_age_s": round(t - sess.created_at, 1) if sess else -1,
                    },
                    ground_truth=ground_truth,
                )
            )
            return {"status": 403, "reason": reason}

        if sess is None:
            return deny("invalid_session")
        if sess.user_id in self.blocked_principals:
            return deny("principal_blocked")
        if spec is None:
            return deny("unknown_command")
        if self.enforce_rbac and command not in ROLE_PERMISSIONS.get(sess.role, set()):
            return deny("rbac_denied")
        if self.enforce_rate_limit and not self._rate_ok(sess.user_id, t):
            return deny("rate_limited")
        if self.enforce_pass_window and not self.ground_station.visible(t):
            return deny("outside_pass_window")

        # authorized: log the intent, then sign and uplink
        self.bus.publish(
            Event(
                ts=t, source=SRC_API_COMMAND, event_type="command.submit",
                actor=sess.user_id,
                target=self.ground_station.spacecraft.spacecraft_id,
                outcome=OUTCOME_SUCCESS, src_ip=ip,
                attrs={
                    "command": command, "args": args, "reason": "authorized",
                    "role": sess.role, "critical": spec["critical"],
                    "session_age_s": round(t - sess.created_at, 1),
                },
                ground_truth=ground_truth,
            )
        )
        return self.uplink(command, args, t, sess.user_id, ip, ground_truth,
                           spoof_tag=spoof_tag, force_seq=force_seq)

    def uplink(
        self, command: str, args: dict, t: float, actor: str, src_ip: str,
        ground_truth: str, spoof_tag: bool = False, force_seq: Optional[int] = None,
    ) -> dict:
        """Frame, sign and hand a telecommand to the ground station."""
        spec = COMMAND_CATALOG.get(command, {"apid": 0x24})
        seq = self._tc_seq if force_seq is None else force_seq
        if force_seq is None:
            self._tc_seq += 1
        pkt = SpacePacket(apid=spec["apid"], seq=seq, kind="TC",
                          payload={"command": command, "args": args}, emitted_at=t)
        key = self.ground_station.spacecraft.sa.key
        pkt.tag = ("00" * 16) if spoof_tag else sign(key, pkt.payload_bytes(), seq)
        verdict = self.ground_station.transmit(pkt, t, actor, src_ip, ground_truth)
        return {"status": 202 if verdict["accepted"] else 409, **verdict}

    def _rate_ok(self, user_id: str, t: float) -> bool:
        q = self._recent_cmds[user_id]
        q.append(t)
        while q and q[0] < t - 60.0:
            q.popleft()
        return len(q) <= self.rate_limit_per_min
