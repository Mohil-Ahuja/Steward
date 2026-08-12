"""Sliding-window rate limits and spend budgets.

Two obligations share this machinery. A *rate limit* caps how many times a tool
may be called; a *budget* caps the summed value of a numeric argument. Both
matter, and neither substitutes for the other: a per-call bound of
``amount <= 100`` does nothing to stop two hundred consecutive refunds of 100,
which is exactly the shape an agent stuck in a retry loop produces.

**Why not fixed windows.** The obvious implementation buckets time into
intervals and counts within each. It is also trivially bypassed: a limit of
10/hour with hourly buckets permits 20 calls in two minutes by placing 10 at
:59 and 10 at :01. This module uses the standard weighted sliding-window
counter instead -- the current bucket's count plus a decaying fraction of the
previous bucket's -- which bounds the true rate over any window at a small
constant factor of memory. The approximation is slightly conservative near a
boundary, which is the correct direction to err.

**Consumption is committed before the call.** A limit that were only recorded
after a successful call would let a tool that times out be retried without
bound. The reservation is taken first and refunded only if the call is refused
downstream of this check.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import UsageCounter


@dataclass
class LimitOutcome:
    allowed: bool
    observed: float
    limit: float
    window_seconds: int
    retry_after_seconds: int = 0

    @property
    def reason(self) -> str:
        if self.allowed:
            return "within limit"
        return (
            f"limit of {self.limit:g} per {self.window_seconds}s exceeded "
            f"(observed {self.observed:.2f}); retry in {self.retry_after_seconds}s"
        )


def _window_start(now: datetime, window_seconds: int) -> datetime:
    """Align a timestamp down to the start of its bucket."""
    epoch_seconds = int(now.timestamp())
    return datetime.fromtimestamp(
        epoch_seconds - (epoch_seconds % window_seconds), tz=UTC
    )


async def _bucket(
    session: AsyncSession,
    principal: str,
    counter_key: str,
    window_start: datetime,
    window_seconds: int,
) -> UsageCounter:
    existing = (
        await session.execute(
            select(UsageCounter).where(
                UsageCounter.principal == principal,
                UsageCounter.counter_key == counter_key,
                UsageCounter.window_start == window_start,
            )
        )
    ).scalar_one_or_none()

    if existing is not None:
        return existing

    created = UsageCounter(
        principal=principal,
        counter_key=counter_key,
        window_start=window_start,
        window_seconds=window_seconds,
        count=0,
        amount=0.0,
    )
    session.add(created)
    await session.flush()
    return created


async def _observed(
    session: AsyncSession,
    principal: str,
    counter_key: str,
    window_seconds: int,
    now: datetime,
    *,
    use_amount: bool,
) -> tuple[float, UsageCounter]:
    """Weighted estimate of usage across the trailing window."""
    current_start = _window_start(now, window_seconds)
    previous_start = current_start - timedelta(seconds=window_seconds)

    current = await _bucket(session, principal, counter_key, current_start, window_seconds)
    previous = (
        await session.execute(
            select(UsageCounter).where(
                UsageCounter.principal == principal,
                UsageCounter.counter_key == counter_key,
                UsageCounter.window_start == previous_start,
            )
        )
    ).scalar_one_or_none()

    def value(bucket: UsageCounter | None) -> float:
        if bucket is None:
            return 0.0
        return float(bucket.amount) if use_amount else float(bucket.count)

    # Fraction of the previous bucket still inside the trailing window.
    elapsed = (now - current_start).total_seconds()
    overlap = max(0.0, 1.0 - (elapsed / window_seconds))

    return value(current) + value(previous) * overlap, current


async def consume(
    session: AsyncSession,
    *,
    principal: str,
    counter_key: str,
    limit: float,
    window_seconds: int,
    amount: float = 1.0,
    use_amount: bool = False,
    now: datetime | None = None,
) -> LimitOutcome:
    """Check the limit and, if the call fits, record the consumption."""
    now = now or datetime.now(UTC)
    observed, current = await _observed(
        session, principal, counter_key, window_seconds, now, use_amount=use_amount
    )

    if observed + amount > limit:
        elapsed = (now - _window_start(now, window_seconds)).total_seconds()
        return LimitOutcome(
            allowed=False,
            observed=observed,
            limit=limit,
            window_seconds=window_seconds,
            retry_after_seconds=max(1, int(window_seconds - elapsed)),
        )

    current.count += 1
    current.amount = float(current.amount) + amount
    await session.commit()

    return LimitOutcome(
        allowed=True,
        observed=observed + amount,
        limit=limit,
        window_seconds=window_seconds,
    )


async def refund(
    session: AsyncSession,
    *,
    principal: str,
    counter_key: str,
    window_seconds: int,
    amount: float = 1.0,
    now: datetime | None = None,
) -> None:
    """Return a reservation when the call did not ultimately happen.

    Called when a later stage refuses the call -- an approval that was denied,
    say. Without this an operator's refusal would silently burn the agent's
    quota, and repeated refusals would look like a rate-limit breach.
    """
    now = now or datetime.now(UTC)
    current_start = _window_start(now, window_seconds)
    bucket = (
        await session.execute(
            select(UsageCounter).where(
                UsageCounter.principal == principal,
                UsageCounter.counter_key == counter_key,
                UsageCounter.window_start == current_start,
            )
        )
    ).scalar_one_or_none()

    if bucket is None:
        return

    bucket.count = max(0, bucket.count - 1)
    bucket.amount = max(0.0, float(bucket.amount) - amount)
    await session.commit()


async def purge_expired(
    session: AsyncSession, *, older_than_seconds: int = 86_400, now: datetime | None = None
) -> int:
    """Drop counter rows no longer inside anyone's trailing window."""
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(seconds=older_than_seconds)
    rows = (
        await session.execute(
            select(UsageCounter).where(UsageCounter.window_start < cutoff)
        )
    ).scalars()

    removed = 0
    for row in rows:
        await session.delete(row)
        removed += 1
    await session.commit()
    return removed
