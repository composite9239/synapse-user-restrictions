import enum
import re
from enum import Enum
from typing import Any, Dict, Iterable, List, Pattern, Set, TypeVar, cast, Optional  # Added Optional here

import attr

ConfigDict = Dict[str, Any]


def check_and_compile_regex(value: Any) -> Pattern[str]:
    """
    Given a value from the configuration, which is validated to be a string,
    compiles and returns a regular expression.
    """
    if not isinstance(value, str):
        raise ValueError("Regex patterns should be specified as strings.")

    try:
        return re.compile(value)
    except re.error as e:
        raise ValueError(f"Invalid regex '{value}': {e.msg}")


def check_all_permissions_understood(permissions: Iterable[str]) -> None:
    """
    Checks that all the permissions contained in the list of permissions are
    ones that we understand and recognise.
    """
    for permission in permissions:
        if permission not in ALL_UNDERSTOOD_PERMISSIONS:
            nice_list_of_understood_permissions = ", ".join(
                sorted(ALL_UNDERSTOOD_PERMISSIONS)
            )
            raise ValueError(
                f"{permission!r} is not a permission recognised "
                f"by the User Restrictions module; "
                f"try one of: {nice_list_of_understood_permissions}"
            )


T = TypeVar("T")


def check_list_elements_are_strings(
    input: List[Any], failure_message: str
) -> List[str]:
    """
    Checks that all elements in a list are of the specified type, casting it upon
    success.
    """
    for ele in input:
        if not isinstance(ele, str):
            raise ValueError(failure_message)

    return cast(List[str], input)


class RuleResult(Enum):
    NoDecision = enum.auto()
    Allow = enum.auto()
    Deny = enum.auto()


@attr.s(auto_attribs=True, frozen=True, slots=True)
class RegexMatchRule:
    """
    A single rule that performs either a regex match or an exact match.
    """

    # regex pattern to match users against, or None if exact_matches is used
    regex: Optional[Pattern[str]]

    # set of exact user IDs to match, or None if regex is used
    exact_matches: Optional[Set[str]]

    # permissions to allow
    allow: Set[str]

    # permissions to deny
    deny: Set[str]

    def apply(self, user_id: str, permission: str) -> RuleResult:
        """
        Applies the rule, returning a rule result.

        Arguments:
            user_id: the Matrix ID (@bob:example.org) of the user being checked
            permission: permission string identifying what kind of permission
                is being sought
        """
        if self.regex is not None:
            if not self.regex.fullmatch(user_id):
                return RuleResult.NoDecision
        elif self.exact_matches is not None:
            if user_id not in self.exact_matches:
                return RuleResult.NoDecision
        else:
            raise ValueError("Rule has neither regex nor exact_matches set.")

        if permission in self.allow:
            return RuleResult.Allow

        if permission in self.deny:
            return RuleResult.Deny

        return RuleResult.NoDecision

    @staticmethod
    def from_config(rule: ConfigDict) -> "RegexMatchRule":
        if "match" not in rule:
            raise ValueError("Rules must have a 'match' field")

        match_value = rule["match"]
        if isinstance(match_value, str):
            # Single regex pattern
            regex_pattern = check_and_compile_regex(match_value)
            exact_matches = None
        elif isinstance(match_value, list):
            # List of exact user IDs
            exact_matches = set(check_list_elements_are_strings(
                match_value, "Rule's 'match' list must contain strings."
            ))
            regex_pattern = None
        else:
            raise ValueError("Rule's 'match' must be a string or a list of strings.")

        if "allow" in rule:
            if not isinstance(rule["allow"], list):
                raise ValueError("Rule's 'allow' field must be a list.")
            allow_list = check_list_elements_are_strings(
                rule["allow"], "Rule's 'allow' field must be a list of strings."
            )
            check_all_permissions_understood(allow_list)
        else:
            allow_list = []

        if "deny" in rule:
            if not isinstance(rule["deny"], list):
                raise ValueError("Rule's 'deny' field must be a list.")
            deny_list = check_list_elements_are_strings(
                rule["deny"], "Rule's 'deny' field must be a list of strings."
            )
            check_all_permissions_understood(deny_list)
        else:
            deny_list = []

        return RegexMatchRule(
            regex=regex_pattern,
            exact_matches=exact_matches,
            allow=set(allow_list),
            deny=set(deny_list)
        )


@attr.s(auto_attribs=True, frozen=True, slots=True)
class UserRestrictionsModuleConfig:
    """
    The root-level configuration.
    """

    # A list of rules.
    rules: List[RegexMatchRule]

    # If the rules don't make a judgement about a user for a permission,
    # this is a list of denied-by-default permissions.
    default_deny: Set[str]

    @staticmethod
    def from_config(config_dict: ConfigDict) -> "UserRestrictionsModuleConfig":
        if "rules" not in config_dict:
            raise ValueError("'rules' list not specified in module configuration.")

        if not isinstance(config_dict["rules"], list):
            raise ValueError("'rules' should be a list.")

        rules = []
        for index, rule in enumerate(config_dict["rules"]):
            if not isinstance(rule, dict):
                raise ValueError(
                    f"Rules should be dicts. "
                    f"Rule number {index + 1} is not (found: {type(rule).__name__})."
                )

            rules.append(RegexMatchRule.from_config(rule))

        default_deny = config_dict.get("default_deny")
        if default_deny is not None:
            if not isinstance(default_deny, list):
                raise ValueError("'default_deny' should be a list (or unspecified).")
            check_list_elements_are_strings(
                default_deny, "'default_deny' should be a list of strings."
            )
            check_all_permissions_understood(default_deny)

        return UserRestrictionsModuleConfig(
            rules=rules,
            default_deny=set(default_deny) if default_deny is not None else set(),
        )


INVITE = "invite"
CREATE_ROOM = "create_room"
RECEIVE_INVITES = "receive_invites"
INVITE_ALL = "invite_all"
ALL_UNDERSTOOD_PERMISSIONS = frozenset({INVITE, CREATE_ROOM, RECEIVE_INVITES, INVITE_ALL})
