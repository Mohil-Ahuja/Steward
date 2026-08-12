"""Audit chain tamper-evidence, redaction, rate limits and approvals."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, update

from steward import approvals, audit, ratelimit
from steward.audit.chain import verify_events
from steward.audit.redaction import redact, redact_text
from steward.models import AuditEvent

# pytest-asyncio runs in auto mode (see pyproject), so async tests need no mark.


async def _write(session, count=5, **overrides):
    for index in range(count):
        await audit.record(
            session,
            principal=overrides.get("principal", "agent-a"),
            server="crm",
            tool="contacts.read",
            arguments={"i": index},
            decision="denied",
            reason="test",
            reason_code="explicit_deny",
        )


class TestAuditChain:
    async def test_fresh_chain_is_intact(self, session):
        await _write(session)
        report = await audit.verify_chain(session)
        assert report.intact
        assert report.events_checked == 5
        assert report.head_sequence == 5

    async def test_in_place_edit_detected(self, session):
        """Flipping a denial to an allow must not go unnoticed."""
        await _write(session)
        await session.execute(
            update(AuditEvent).where(AuditEvent.sequence == 3).values(decision="allowed")
        )
        await session.commit()

        report = await audit.verify_chain(session)
        assert not report.intact
        assert any(item.kind == "hash_mismatch" for item in report.breaks)

    async def test_deletion_detected(self, session):
        await _write(session)
        event = (
            await session.execute(select(AuditEvent).where(AuditEvent.sequence == 2))
        ).scalar_one()
        await session.delete(event)
        await session.commit()

        report = await audit.verify_chain(session)
        assert not report.intact
        kinds = {item.kind for item in report.breaks}
        assert "gap" in kinds and "link_mismatch" in kinds

    async def test_chain_cannot_be_forged_without_the_key(self, session):
        await _write(session)
        rows = list(
            (
                await session.execute(
                    select(AuditEvent)
                    .order_by(AuditEvent.sequence)
                    .execution_options(populate_existing=True)
                )
            ).scalars()
        )
        assert not verify_events(rows, key=b"wrong-key").intact

    async def test_verification_reads_through_the_identity_map(self, session):
        """Regression: a cached object once let an edited log verify as intact."""
        await _write(session)
        assert (await audit.verify_chain(session)).intact  # populates the cache
        await session.execute(
            update(AuditEvent).where(AuditEvent.sequence == 1).values(principal="mallory")
        )
        await session.commit()
        assert not (await audit.verify_chain(session)).intact

    async def test_checkpoint_reports_head(self, session):
        await _write(session, count=3)
        checkpoint = await audit.checkpoint(session)
        assert checkpoint["head_sequence"] == 3
        assert checkpoint["intact"] is True
        assert len(checkpoint["head_hash"]) == 64


class TestRedaction:
    def test_key_based_redaction(self):
        out = redact({"password": "hunter2", "id": 1}, {"password"})
        assert out["password"] == "[REDACTED]"
        assert out["id"] == 1

    def test_value_based_redaction_finds_secrets_under_innocuous_keys(self):
        out = redact({"note": "use sk-abcdefghijklmnop1234 to auth"}, set())
        assert "sk-abcdefghijklmnop1234" not in out["note"]

    def test_structure_is_preserved(self):
        out = redact({"a": {"b": [{"token": "x"}]}}, {"token"})
        assert out["a"]["b"][0]["token"] == "[REDACTED]"

    def test_luhn_check_avoids_redacting_ordinary_numbers(self):
        assert "4111111111111111" not in redact_text("card 4111111111111111")
        # Not a valid card number, so it survives.
        assert "1234567890123" in redact_text("order 1234567890123")

    def test_depth_is_bounded(self):
        nested: dict = {}
        cursor = nested
        for _ in range(50):
            cursor["next"] = {}
            cursor = cursor["next"]
        assert redact(nested, set()) is not None

    async def test_arguments_are_redacted_before_persisting(self, session):
        await audit.record(
            session,
            principal="agent-a",
            server="crm",
            tool="contacts.read",
            arguments={"password": "hunter2"},
            decision="allowed",
            reason="ok",
            reason_code="allowed",
        )
        row = (await session.execute(select(AuditEvent))).scalars().first()
        assert row.arguments["password"] == "[REDACTED]"


class TestRateLimits:
    async def test_limit_blocks_beyond_the_cap(self, session):
        for _ in range(3):
            outcome = await ratelimit.consume(
                session, principal="a", counter_key="crm:read", limit=3, window_seconds=60
            )
            assert outcome.allowed

        blocked = await ratelimit.consume(
            session, principal="a", counter_key="crm:read", limit=3, window_seconds=60
        )
        assert not blocked.allowed
        assert blocked.retry_after_seconds > 0

    async def test_limits_are_per_principal(self, session):
        await ratelimit.consume(
            session, principal="a", counter_key="k", limit=1, window_seconds=60
        )
        other = await ratelimit.consume(
            session, principal="b", counter_key="k", limit=1, window_seconds=60
        )
        assert other.allowed

    async def test_budget_sums_amounts_not_calls(self, session):
        for _ in range(4):
            outcome = await ratelimit.consume(
                session,
                principal="a",
                counter_key="budget",
                limit=1000,
                window_seconds=3600,
                amount=200.0,
                use_amount=True,
            )
            assert outcome.allowed

        # Fifth call of 200 would total 1000... the sixth exceeds.
        await ratelimit.consume(
            session, principal="a", counter_key="budget", limit=1000,
            window_seconds=3600, amount=200.0, use_amount=True,
        )
        over = await ratelimit.consume(
            session, principal="a", counter_key="budget", limit=1000,
            window_seconds=3600, amount=200.0, use_amount=True,
        )
        assert not over.allowed

    async def test_refund_returns_a_reservation(self, session):
        await ratelimit.consume(
            session, principal="a", counter_key="k", limit=1, window_seconds=60
        )
        await ratelimit.refund(session, principal="a", counter_key="k", window_seconds=60)
        again = await ratelimit.consume(
            session, principal="a", counter_key="k", limit=1, window_seconds=60
        )
        assert again.allowed

    async def test_sliding_window_counts_the_previous_bucket(self, session):
        """A fixed window would allow a burst across a boundary; this must not.

        The clock is pinned rather than taken from ``now()``. The weighted
        window carries forward ``1 - elapsed/window`` of the previous bucket,
        so the result genuinely depends on where in the minute the test runs --
        with a live clock this passes or fails according to the wall clock,
        which is exactly the kind of flake that erodes trust in a suite.
        """
        now = datetime(2026, 1, 1, 12, 0, 5, tzinfo=UTC)  # 5s into the bucket
        window = 60
        for _ in range(5):
            await ratelimit.consume(
                session, principal="a", counter_key="k", limit=5,
                window_seconds=window, now=now,
            )
        just_after = now + timedelta(seconds=window)
        outcome = await ratelimit.consume(
            session, principal="a", counter_key="k", limit=5,
            window_seconds=window, now=just_after,
        )
        assert not outcome.allowed


class TestApprovals:
    async def _pending(self, session, **overrides):
        return await approvals.create_request(
            session,
            correlation_id="c1",
            principal=overrides.get("principal", "agent-a"),
            server=overrides.get("server", "billing"),
            tool=overrides.get("tool", "refund.issue"),
            arguments=overrides.get("arguments", {"amount": 100}),
            risk_tier="sensitive",
        )

    async def test_approved_token_permits_the_call(self, session):
        request = await self._pending(session)
        await approvals.resolve(session, request.id, approved=True, decided_by="ops")
        outcome = await approvals.check_token(
            session, request.id, principal="agent-a", server="billing",
            tool="refund.issue", arguments={"amount": 100},
        )
        assert outcome.is_approved

    async def test_token_is_bound_to_the_tool(self, session):
        """Confused deputy: an approval must not transfer to another tool."""
        request = await self._pending(session)
        await approvals.resolve(session, request.id, approved=True, decided_by="ops")
        outcome = await approvals.check_token(
            session, request.id, principal="agent-a", server="crm",
            tool="contacts.delete", arguments={"amount": 100},
        )
        assert outcome.status == approvals.REJECTED

    async def test_token_is_bound_to_the_principal(self, session):
        request = await self._pending(session)
        await approvals.resolve(session, request.id, approved=True, decided_by="ops")
        outcome = await approvals.check_token(
            session, request.id, principal="agent-b", server="billing",
            tool="refund.issue", arguments={"amount": 100},
        )
        assert outcome.status == approvals.REJECTED

    async def test_token_is_bound_to_the_arguments(self, session):
        """An approval for 100 must not authorise 9999."""
        request = await self._pending(session)
        await approvals.resolve(session, request.id, approved=True, decided_by="ops")
        outcome = await approvals.check_token(
            session, request.id, principal="agent-a", server="billing",
            tool="refund.issue", arguments={"amount": 9999},
        )
        assert outcome.status == approvals.REJECTED
        assert "different arguments" in outcome.detail

    async def test_rejection_is_final(self, session):
        request = await self._pending(session)
        await approvals.resolve(session, request.id, approved=False, decided_by="ops")
        with pytest.raises(ValueError):
            await approvals.resolve(session, request.id, approved=True, decided_by="ops")

    async def test_expired_approval_is_not_usable(self, session):
        request = await approvals.create_request(
            session,
            correlation_id="c1",
            principal="agent-a",
            server="billing",
            tool="refund.issue",
            arguments={},
            ttl_seconds=-1,
        )
        outcome = await approvals.check_token(
            session, request.id, principal="agent-a", server="billing",
            tool="refund.issue", arguments={},
        )
        assert outcome.status == approvals.EXPIRED

    async def test_input_required_result_is_spec_shaped(self, session):
        request = await self._pending(session)
        payload = approvals.input_required_result(request)
        assert payload["resultType"] == "input_required"
        assert payload["requestState"] == request.id
        assert "steward_approval" in payload["inputRequests"]
        assert (
            payload["inputRequests"]["steward_approval"]["method"] == "elicitation/create"
        )
