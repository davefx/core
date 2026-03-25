"""Merging of policies."""

from __future__ import annotations

from collections.abc import Iterable
from typing import cast

from .const import SUBCAT_ALL
from .types import CategoryType, PolicyType


def merge_policies(policies: list[PolicyType]) -> PolicyType:
    """Merge policies."""
    new_policy: dict[str, CategoryType] = {}
    seen: set[str] = set()
    for policy in policies:
        for category in policy:
            if category in seen:
                continue
            seen.add(category)
            new_policy[category] = _merge_policies(
                [policy.get(category) for policy in policies]
            )
    cast(PolicyType, new_policy)
    return new_policy


def _merge_policies(sources: list[CategoryType]) -> CategoryType:
    """Merge a policy.

    When merging policies, deny always takes precedence (deny-overrides-allow):
    False > True > Dict > None

    False: explicit deny (always wins)
    True: allow everything
    Dict: specify more granular permissions
    None: no opinion

    When a True source is merged with dict sources that contain deny (False)
    values, the True is expanded into {all: True} so that the deny entries
    are preserved while maintaining "allow everything else" semantics.

    If the dict sources contain no deny values, True wins outright
    (backward-compatible behavior).

    If there are multiple sources with a dict as policy, we recursively
    merge each key in the source.
    """
    has_true = False
    dict_sources: list[dict] = []

    for source in sources:
        if source is None:
            continue

        # A source that's False (deny) always wins. Shortcut return.
        if source is False:
            return False

        if source is True:
            has_true = True
            continue

        assert isinstance(source, dict)
        dict_sources.append(source)

    if not has_true and not dict_sources:
        return None

    if has_true and not dict_sources:
        return True

    if has_true:
        # Only expand True into {all: True} when dict sources contain
        # deny values. Otherwise True wins outright (backward compatible).
        if not _contains_deny(dict_sources):
            return True

        # Expand True into {all: True} so the "allow everything" intent
        # is preserved while specific deny entries from dict sources can
        # override individual items.
        dict_sources.append({SUBCAT_ALL: True})

    policy: dict[str, CategoryType] = {}
    seen: set[str] = set()

    for source in dict_sources:
        for key in source:
            if key in seen:
                continue
            seen.add(key)

            key_sources: list[CategoryType] = [
                src.get(key) for src in dict_sources
            ]

            # When a True source was expanded, propagate the True intent
            # to each key found in dict sources so that deny values for
            # specific sub-keys can override while other sub-keys remain
            # allowed.
            if has_true and key != SUBCAT_ALL:
                key_sources.append(True)

            policy[key] = _merge_policies(key_sources)

    return cast(CategoryType, policy) if policy else None


def _contains_deny(sources: Iterable[object]) -> bool:
    """Check if any source contains a False (deny) value at any level."""
    for source in sources:
        if source is False:
            return True
        if isinstance(source, dict):
            if _contains_deny(source.values()):
                return True
    return False
