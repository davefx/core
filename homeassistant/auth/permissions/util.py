"""Helpers to deal with permissions."""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from .const import SUBCAT_ALL
from .models import PermissionLookup
from .types import CategoryType, SubCategoryDict, ValueType

type LookupFunc = Callable[[PermissionLookup, SubCategoryDict, str], ValueType | None]
type SubCatLookupType = dict[str, LookupFunc]


def lookup_all(
    perm_lookup: PermissionLookup, lookup_dict: SubCategoryDict, object_id: str
) -> ValueType:
    """Look up permission for all."""
    # In case of ALL category, lookup_dict IS the schema.
    return cast(ValueType, lookup_dict)


def compile_policy(
    policy: CategoryType, subcategories: SubCatLookupType, perm_lookup: PermissionLookup
) -> Callable[[str, str], bool]:
    """Compile policy into a function that tests policy.

    Subcategories are mapping key -> lookup function, ordered by highest
    priority first.
    """
    # None, empty dict
    if policy is None or (isinstance(policy, dict) and not policy):

        def apply_policy_deny_all(entity_id: str, key: str) -> bool:
            """Decline all."""
            return False

        return apply_policy_deny_all

    # Explicit deny of entire category
    if policy is False:

        def apply_policy_explicit_deny_all(entity_id: str, key: str) -> bool:
            """Explicitly deny all."""
            return False

        return apply_policy_explicit_deny_all

    if policy is True:

        def apply_policy_allow_all(entity_id: str, key: str) -> bool:
            """Approve all."""
            return True

        return apply_policy_allow_all

    assert isinstance(policy, dict)

    funcs: list[Callable[[str, str], bool | None]] = []

    for key, lookup_func in subcategories.items():
        lookup_value = policy.get(key)

        if lookup_value is True:
            # This subcategory allows all. Don't short-circuit because
            # lower-priority subcategories might have deny entries that
            # must take precedence.
            funcs.append(_always_grant)
        elif lookup_value is False:
            # This subcategory explicitly denies all.
            funcs.append(_always_deny)
        elif lookup_value is not None:
            funcs.append(_gen_dict_test_func(perm_lookup, lookup_func, lookup_value))

    if not funcs:

        def apply_policy_no_funcs(object_id: str, key: str) -> bool:
            """No matching subcategories, deny."""
            return False

        return apply_policy_no_funcs

    if len(funcs) == 1:
        func = funcs[0]

        def apply_policy_func(object_id: str, key: str) -> bool:
            """Apply a single policy function."""
            result = func(object_id, key)
            if result is None:
                return False
            return result

        return apply_policy_func

    def apply_policy_funcs(object_id: str, key: str) -> bool:
        """Apply several policy functions.

        Deny always wins: if any subcategory returns False, the result is
        False regardless of priority. Otherwise, the first non-None result
        (by priority order) determines the outcome.
        """
        first_result: bool | None = None
        for func in funcs:
            result = func(object_id, key)
            if result is False:
                return False
            if first_result is None and result is not None:
                first_result = result
        if first_result is None:
            return False
        return first_result

    return apply_policy_funcs


def _always_grant(object_id: str, key: str) -> bool:
    """Always grant access."""
    return True


def _always_deny(object_id: str, key: str) -> bool | None:
    """Always deny access."""
    return False


def _gen_dict_test_func(
    perm_lookup: PermissionLookup, lookup_func: LookupFunc, lookup_dict: SubCategoryDict
) -> Callable[[str, str], bool | None]:
    """Generate a lookup function."""

    def test_value(object_id: str, key: str) -> bool | None:
        """Test if permission is allowed based on the keys."""
        schema: ValueType = lookup_func(perm_lookup, lookup_dict, object_id)

        if schema is None or isinstance(schema, bool):
            return schema

        assert isinstance(schema, dict)

        result = schema.get(key)
        if result is None:
            # Fall back to the "all" key as a wildcard default for
            # unspecified permission keys at this level.
            return schema.get(SUBCAT_ALL)
        return result

    return test_value


def test_all(policy: CategoryType, key: str) -> bool:
    """Test if a policy has an ALL access for a specific key."""
    if not isinstance(policy, dict):
        return bool(policy)

    all_policy = policy.get(SUBCAT_ALL)

    if not isinstance(all_policy, dict):
        return bool(all_policy)

    return all_policy.get(key, False)  # type: ignore[no-any-return]
