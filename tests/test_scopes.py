"""Scope algebra, especially glob-language containment."""

import pytest

from steward.policy.scopes import (
    Scope,
    ScopeError,
    attenuate,
    find_redundant,
    glob_contains,
    parse_scopes,
)


@pytest.mark.parametrize(
    "outer,inner,expected",
    [
        ("*", "anything", True),
        ("*", "*", True),
        ("a*", "ab*", True),
        ("ab*", "a*", False),          # the asymmetry string comparison misses
        ("*x", "x*", False),           # overlapping but neither contains
        ("x*", "*x", False),
        ("a?c", "abc", True),
        ("abc", "a?c", False),
        ("a*b*", "a*b", True),
        ("a*b", "a*b*", False),
        ("*.read", "contacts.read", True),
        ("contacts.*", "contacts.read", True),
        ("contacts.read", "contacts.*", False),
        ("*a*", "*ab*", True),
        ("*ab*", "*a*", False),
        ("a*", "a", True),
        ("a", "a*", False),
    ],
)
def test_glob_containment(outer, inner, expected):
    assert glob_contains(outer, inner) is expected


def test_containment_is_reflexive_and_transitive():
    broad, middle, narrow = "crm:*", "crm:contacts.*", "crm:contacts.read"
    a, b, c = Scope.parse(broad), Scope.parse(middle), Scope.parse(narrow)
    assert a.contains(a)
    assert a.contains(b) and b.contains(c)
    assert a.contains(c)  # transitivity
    assert not c.contains(a)


def test_attenuation_never_widens_authority():
    held = [Scope.parse("crm:contacts.read")]
    requested = parse_scopes("crm:* crm:contacts.read billing:refund.issue")
    granted = {str(scope) for scope in attenuate(held, requested)}
    assert granted == {"crm:contacts.read"}


def test_blanket_scope_contains_everything():
    blanket = Scope.parse("*:*")
    assert blanket.is_blanket()
    for candidate in ("crm:contacts.delete", "billing:refund.issue", "a:b"):
        assert blanket.contains(Scope.parse(candidate))


def test_find_redundant_reports_subsumed_grants():
    scopes = parse_scopes("crm:contacts.read crm:*")
    pairs = find_redundant(scopes)
    assert [(str(a), str(b)) for a, b in pairs] == [("crm:contacts.read", "crm:*")]


def test_specificity_orders_narrow_above_broad():
    narrow = Scope.parse("crm:contacts.read")
    broad = Scope.parse("crm:*")
    assert narrow.specificity() > broad.specificity()


@pytest.mark.parametrize("bad", ["", "no-separator", "crm:", ":tool", "a:b:c"])
def test_malformed_scopes_rejected(bad):
    with pytest.raises(ScopeError):
        Scope.parse(bad)


def test_matching_concrete_calls():
    scope = Scope.parse("crm:contacts.*")
    assert scope.matches("crm", "contacts.read")
    assert not scope.matches("crm", "invoice.get")
    assert not scope.matches("billing", "contacts.read")
