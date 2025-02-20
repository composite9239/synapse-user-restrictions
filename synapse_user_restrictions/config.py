# Copyright 2021 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import enum
import re
from enum import Enum
from typing import Any, Dict, Iterable, List, Pattern, Set, TypeVar, cast

import attr

from synapse.module_api import RuleResult
from attr import s as attr_s, frozen

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
    A single rule that performs a regex match.
    """

    # regex pattern to match users against
    match: Pattern[str]

    # permissions to allow
    allow: Set[str]

    # permissions to deny
    deny: Set[str]

    def apply(self, user_id: str, permission: str) -> RuleResult:
        """
        Applies a regular expression match rule, returning a rule result.

        Arguments:
            user_id: the Matrix ID (@bob:example.org) of the user being checked
            permission: permission string identifying what kind of permission
                is being sought
        """
        if not self.match.fullmatch(user_id):
            return RuleResult.NoDecision

        if permission in self.allow:
            return RuleResult.Allow

        if permission in self.deny:
            return RuleResult.Deny

        return RuleResult.NoDecision

    @staticmethod
    def from_config(rule: ConfigDict) -> "RegexMatchRule":
        if "match" not in rule:
            raise ValueError("Rules must have a 'match' field")
        match_pattern = check_and_compile_regex(rule["match"])

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
            match=match_pattern, allow=set(allow_list), deny=set(deny_list)
        )

@attr_s(auto_attribs=True, frozen=True, slots=True)
class ExactMatchRule:
    """
    A single rule that performs exact user ID matches.
    """
    # Set of exact user IDs to match against
    match: Set[str]
    
    # Permissions to allow
    allow: Set[str]
    
    # Permissions to deny
    deny: Set[str]

    def apply(self, user_id: str, permission: str) -> RuleResult:
        """
        Applies an exact match rule, returning a rule result.

        Arguments:
            user_id: The Matrix ID (e.g., @bob:example.org) of the user being checked
            permission: The permission string identifying what is being sought
        """
        if user_id not in self.match:
            return RuleResult.NoDecision

        if permission in self.allow:
            return RuleResult.Allow
        if permission in self.deny:
            return RuleResult.Deny
        return RuleResult.NoDecision

    @staticmethod
    def from_config(rule: dict) -> "ExactMatchRule":
        """
        Creates an ExactMatchRule from a configuration dictionary.
        """
        if "match" not in rule:
            raise ValueError("Rules must have a 'match' field")
        if not isinstance(rule["match"], list):
            raise ValueError("For exact match rules, 'match' must be a list of strings")
        
        match_list = check_list_elements_are_strings(
            rule["match"], "Exact match 'match' field must be a list of strings"
        )

        allow_list = []
        if "allow" in rule:
            if not isinstance(rule["allow"], list):
                raise ValueError("Rule's 'allow' field must be a list")
            allow_list = check_list_elements_are_strings(
                rule["allow"], "Rule's 'allow' field must be a list of strings"
            )
            check_all_permissions_understood(allow_list)

        deny_list = []
        if "deny" in rule:
            if not isinstance(rule["deny"], list):
                raise ValueError("Rule's 'deny' field must be a list")
            deny_list = check_list_elements_are_strings(
                rule["deny"], "Rule's 'deny' field must be a list of strings"
            )
            check_all_permissions_understood(deny_list)

        return ExactMatchRule(
            match=set(match_list),
            allow=set(allow_list),
            deny=set(deny_list)
        )

from typing import Union
RuleType = Union[RegexMatchRule, ExactMatchRule]

@attr_s(auto_attribs=True, frozen=True, slots=True)
class UserRestrictionsModuleConfig:
    """
    The root-level configuration for the UserRestrictionsModule.
    """
    # List of rules, which can be either RegexMatchRule or ExactMatchRule
    rules: List[RuleType]
    
    # Permissions denied by default if no rule applies
    default_deny: Set[str]

    @staticmethod
    def from_config(config_dict: dict) -> "UserRestrictionsModuleConfig":
        """
        Creates a UserRestrictionsModuleConfig from a configuration dictionary.
        """
        if "rules" not in config_dict:
            raise ValueError("'rules' list not specified in module configuration")
        if not isinstance(config_dict["rules"], list):
            raise ValueError("'rules' should be a list")

        rules = []
        for index, rule in enumerate(config_dict["rules"]):
            if not isinstance(rule, dict):
                raise ValueError(
                    f"Rules should be dicts. Rule number {index + 1} is not "
                    f"(found: {type(rule).__name__})"
                )
            match_field = rule.get("match")
            if isinstance(match_field, str):
                rules.append(RegexMatchRule.from_config(rule))
            elif isinstance(match_field, list):
                rules.append(ExactMatchRule.from_config(rule))
            else:
                raise ValueError(
                    f"Rule number {index + 1}: 'match' must be a string (for regex) "
                    f"or a list of strings (for exact matches)"
                )

        default_deny = config_dict.get("default_deny", [])
        if not isinstance(default_deny, list):
            raise ValueError("'default_deny' should be a list (or unspecified)")
        default_deny_list = check_list_elements_are_strings(
            default_deny, "'default_deny' should be a list of strings"
        )
        check_all_permissions_understood(default_deny_list)

        return UserRestrictionsModuleConfig(
            rules=rules,
            default_deny=set(default_deny_list)
        )


INVITE = "invite"
CREATE_ROOM = "create_room"
RECEIVE_INVITES = "receive_invites"
INVITE_ALL = "invite_all"
ALL_UNDERSTOOD_PERMISSIONS = frozenset({INVITE, CREATE_ROOM, RECEIVE_INVITES, INVITE_ALL})
