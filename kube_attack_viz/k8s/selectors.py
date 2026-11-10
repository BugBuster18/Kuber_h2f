"""Kubernetes label selector semantics (metav1.LabelSelector)."""

from __future__ import annotations

from typing import Mapping


def matches(selector: Mapping | None, labels: Mapping[str, str] | None) -> bool:
    """True if `labels` satisfy a LabelSelector.

    Semantics follow the API: a nil selector matches nothing, an empty
    selector ({}) matches everything; matchLabels and matchExpressions are
    ANDed.
    """
    if selector is None:
        return False
    labels = labels or {}
    for key, value in (selector.get("matchLabels") or {}).items():
        if labels.get(key) != value:
            return False
    for expr in selector.get("matchExpressions") or []:
        key = expr.get("key")
        op = expr.get("operator")
        values = set(expr.get("values") or [])
        present = key in labels
        if op == "In" and not (present and labels[key] in values):
            return False
        if op == "NotIn" and present and labels[key] in values:
            return False
        if op == "Exists" and not present:
            return False
        if op == "DoesNotExist" and present:
            return False
    return True


def matches_service_selector(selector: Mapping[str, str] | None, labels: Mapping[str, str] | None) -> bool:
    """Service.spec.selector is a plain map; empty/None selects no pods."""
    if not selector:
        return False
    labels = labels or {}
    return all(labels.get(k) == v for k, v in selector.items())
