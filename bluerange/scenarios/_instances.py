"""Private deterministic observable generation for evaluators and orchestrators."""

import hashlib
import json
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from bluerange.models import IdentityDefinition, Scenario, SessionDefinition, TelemetryEvent


class EvidenceProfile(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    AMBIGUOUS = "AMBIGUOUS"
    NOISY = "NOISY"


@dataclass(frozen=True)
class _ObservableInstance:
    scenario: Scenario
    instance_fingerprint: str
    evidence_profile: EvidenceProfile


USERS = ("riley", "morgan", "casey", "devon", "taylor", "jordan", "quinn", "avery")
SOURCES = ("198.51.100.24", "203.0.113.77", "192.0.2.146", "198.51.100.91")


def _event(
    step: int,
    offset: int,
    event_type: str,
    identity: str,
    detail: str,
    source_ip: str | None = None,
    asset_id: str | None = None,
    session_id: str | None = None,
) -> TelemetryEvent:
    return TelemetryEvent(
        step=step,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=offset),
        event_type=event_type,
        identity_id=identity,
        source_ip=source_ip,
        asset_id=asset_id,
        session_id=session_id,
        detail=detail,
    )


def _build_observable_instance(
    seed: int, profile: EvidenceProfile | str = EvidenceProfile.COMPLETE, control: bool = False
) -> _ObservableInstance:
    """Build one reproducible semantic instance for the private evaluator path."""
    selected_profile = EvidenceProfile(profile)
    rng = random.Random(seed)
    people = rng.sample(USERS, 3)
    subject, noisy, administrator = people
    service = f"svc-{rng.choice(('ledger', 'billing', 'archive', 'reports'))}"
    identities = [
        IdentityDefinition(id=subject, display_name=subject.title(), role="Business analyst"),
        IdentityDefinition(id=noisy, display_name=noisy.title(), role="Travelling account manager"),
        IdentityDefinition(
            id=administrator,
            display_name=administrator.title(),
            role="Platform administrator",
            critical=True,
        ),
        IdentityDefinition(
            id=service, display_name=service.upper(), role="Production service", critical=True
        ),
    ]
    session_ids = {identity.id: f"s-{rng.getrandbits(48):012x}" for identity in identities}
    sessions = [SessionDefinition(id=session_ids[i.id], identity_id=i.id) for i in identities]
    attack_source, vpn_source = rng.sample(SOURCES, 2)
    events = [
        _event(
            1,
            1,
            "login",
            subject,
            "Successful sign-in with valid credentials",
            attack_source,
            session_id=session_ids[subject],
        ),
        _event(
            1,
            2,
            "login",
            noisy,
            "Successful sign-in through approved corporate VPN",
            vpn_source,
            session_id=session_ids[noisy],
        ),
        _event(
            2,
            3,
            "authentication_context",
            subject,
            "New unmanaged device and unusual geography with no matching travel record"
            if not control
            else "Unusual geography matched an approved travel record and corporate VPN egress",
            attack_source,
            session_id=session_ids[subject],
        ),
        _event(
            2,
            4,
            "token_refresh",
            service,
            "Scheduled service-account token refresh",
            "10.0.4.20",
            session_id=session_ids[service],
        ),
        _event(
            3,
            5,
            "sensitive_app_access",
            subject,
            "First sensitive application access from this unmanaged device"
            if not control
            else "Sensitive application access covered by an approved support ticket",
            asset_id="records-vault",
            session_id=session_ids[subject],
        ),
        _event(
            3,
            6,
            "authentication_context",
            noisy,
            "Late-night VPN reconnect from approved travel destination",
            vpn_source,
            session_id=session_ids[noisy],
        ),
        _event(
            4,
            7,
            "privilege_activity",
            subject,
            "Temporary export privilege requested outside the approved workflow"
            if not control
            else "Temporary export privilege activated under approved change record",
            asset_id="records-vault",
            session_id=session_ids[subject],
        ),
        _event(
            4,
            8,
            "privilege_activity",
            administrator,
            "Privileged administration under approved maintenance change",
            asset_id="identity-console",
            session_id=session_ids[administrator],
        ),
        _event(
            5,
            9,
            "health_check",
            service,
            "Service-account production health check at an unusual but scheduled time",
            asset_id="billing-api",
            session_id=session_ids[service],
        ),
        _event(
            6,
            10,
            "suspicious_data_access",
            subject,
            "Bulk enumeration of sensitive records without a business justification"
            if not control
            else "Bulk sensitive-record export reconciled to the approved audit request",
            asset_id="records-vault",
            session_id=session_ids[subject],
        ),
    ]
    if selected_profile == EvidenceProfile.PARTIAL:
        events = [
            event
            for event in events
            if not (event.identity_id == subject and event.event_type == "privilege_activity")
        ]
    elif selected_profile == EvidenceProfile.AMBIGUOUS:
        events.append(
            _event(
                5,
                11,
                "change_context",
                subject,
                "An approved support ticket fully explains the activity"
                if control
                else "A pending support ticket could explain part, but not all, of the activity",
                asset_id="records-vault",
            )
        )
    elif selected_profile == EvidenceProfile.NOISY:
        for index in range(12, 18):
            identity = rng.choice((noisy, administrator, service))
            events.append(
                _event(
                    rng.randint(1, 6),
                    index,
                    "background_activity",
                    identity,
                    "Routine unrelated telemetry from a monitored application",
                )
            )
    # Bounded sub-second seed jitter varies timing without crossing the one-second
    # causal spacing of the authored sequence.
    timing_rng = random.Random(seed ^ 0xB10E_AA6E)
    events = [
        event.model_copy(
            update={"timestamp": event.timestamp + timedelta(milliseconds=timing_rng.randrange(800))}
        )
        for event in events
    ]
    noncausal = [event for event in events if event.identity_id != subject]
    causal = [event for event in events if event.identity_id == subject]
    rng.shuffle(noncausal)
    events = sorted(causal + noncausal, key=lambda event: (event.step, rng.random()))
    scenario = Scenario(
        schema_version="1.0",
        id="identity-compromise-001",
        version="1.1",
        name="Identity Activity Investigation",
        description="Investigate identity activity amid realistic authentication and administration noise.",
        seed=seed,
        max_steps=10,
        identities=identities,
        sessions=sessions,
        permitted_tools=[
            "search_logs",
            "inspect_identity",
            "get_authentication_history",
            "get_active_sessions",
            "get_asset_context",
            "revoke_session",
            "disable_identity",
            "escalate_to_human",
            "create_incident",
        ],
        telemetry=tuple(events),
    )
    semantic = {
        "scenario": scenario.model_dump(mode="json"),
        "profile": selected_profile.value,
        "control": control,
    }
    fingerprint = hashlib.sha256(
        json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return _ObservableInstance(scenario, fingerprint, selected_profile)
