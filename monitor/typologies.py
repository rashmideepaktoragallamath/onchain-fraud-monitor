"""Plain-language AML context for every reason code.

Shown to analysts next to each alert so a score is never a bare number: what the pattern
is, why compliance teams care, and what to check next. The wording describes common
red-flag indicators used in AML / virtual-asset guidance; it is not legal advice.
"""

from __future__ import annotations

from dataclasses import dataclass

from monitor.reasons import Reason


@dataclass(frozen=True)
class Typology:
    title: str
    meaning: str
    why_it_matters: str
    next_step: str


TYPOLOGIES: dict[str, Typology] = {
    Reason.STRUCTURING.name: Typology(
        "Structuring (smurfing)",
        "Several transfers sit just under an internal review limit.",
        "Splitting an amount to stay below a threshold is a classic red flag for avoiding review.",
        "Add the transfers up and review them as one movement of funds.",
    ),
    Reason.FAN_OUT.name: Typology(
        "One-to-many distribution",
        "One wallet sent funds to many different recipients in a short time.",
        "Spreading money across many wallets (layering) makes the trail harder to follow.",
        "Trace where the recipients send the funds next.",
    ),
    Reason.FAN_IN.name: Typology(
        "Many-to-one consolidation",
        "Many different wallets paid the same recipient in a short time.",
        "Collecting small payments into one wallet can mean proceeds are being pooled, for example from scams.",
        "Check whether the recipient is a known service or a newly created wallet.",
    ),
    Reason.ROUND_TRIP.name: Typology(
        "Round-tripping",
        "Funds went to a wallet and came back in a similar amount.",
        "Circular flows can create fake activity or hide where money really came from.",
        "Look at both legs and the time between them.",
    ),
    Reason.HIGH_VELOCITY.name: Typology(
        "Rapid-fire transfers",
        "One wallet made many transfers within a short window.",
        "Scripts move funds far faster than people, which is typical of layering and account draining. "
        "It is also normal for exchanges and market makers.",
        "Check whether the wallet is a known exchange or service before acting.",
    ),
    Reason.WATCHLISTED.name: Typology(
        "Watchlisted counterparty",
        "A wallet on the watchlist is involved in this transfer.",
        "Dealing with listed addresses can create screening obligations for a regulated business.",
        "Escalate to compliance and keep the evidence.",
    ),
    Reason.LARGE_VALUE.name: Typology(
        "Unusually large transfer",
        "The amount is at or above the configured limit.",
        "Large movements carry most of the value in a laundering scheme, but they are also common "
        "for legitimate treasury moves, so this signal is weak on its own.",
        "Check the counterparty and the likely source of funds.",
    ),
    Reason.NEW_WALLET_BURST.name: Typology(
        "Fresh wallet, large flow",
        "A wallet with almost no history moved a lot of value quickly.",
        "Throwaway wallets are often used to move funds once and disappear.",
        "Find where the wallet was funded from and where the money went.",
    ),
    Reason.ML_ANOMALY.name: Typology(
        "Statistical outlier",
        "Isolation Forest finds this behaviour unlike most recent activity.",
        "It can catch patterns no rule describes, but unusual is not the same as wrong.",
        "Weigh it together with the other signals on the case.",
    ),
}


def for_reasons(names: list[str]) -> list[dict[str, str]]:
    """Typology cards for the given reason names, most serious signals first."""
    order = list(TYPOLOGIES)
    cards = []
    for name in sorted((n for n in names if n in TYPOLOGIES), key=order.index):
        t = TYPOLOGIES[name]
        cards.append(
            {
                "reason": name,
                "title": t.title,
                "meaning": t.meaning,
                "why_it_matters": t.why_it_matters,
                "next_step": t.next_step,
            }
        )
    return cards
