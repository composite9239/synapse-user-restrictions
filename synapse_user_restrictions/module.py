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
from synapse.module_api import ModuleApi
from synapse.module_api.errors import ConfigError
import logging
logger = logging.getLogger(__name__)

from synapse_user_restrictions.config import (
    ALL_UNDERSTOOD_PERMISSIONS,
    CREATE_ROOM,
    INVITE,
    RECEIVE_INVITES,
    INVITE_ALL,
    JOIN_ROOM,
    ConfigDict,
    RuleResult,
    UserRestrictionsModuleConfig,
)

class UserRestrictionsModule:
    def __init__(self, config: UserRestrictionsModuleConfig, api: ModuleApi):
        self._api = api
        self._config = config

        api.register_spam_checker_callbacks(
            user_may_create_room=self.callback_user_may_create_room,
            user_may_invite=self.callback_user_may_invite,
            user_may_join_room=self.callback_user_may_join_room,
        )

    @staticmethod
    def parse_config(config: ConfigDict) -> UserRestrictionsModuleConfig:
        try:
            return UserRestrictionsModuleConfig.from_config(config)
        except (TypeError, ValueError) as e:
            raise ConfigError(f"Failed to parse user restrictions module config: {e}")

    def _apply_rules(self, user_id: str, permission: str) -> bool:
        """
        Apply the rules in-order, returning a boolean result.
        If no rules make a decision, the permission will be allowed by default unless in default_deny.

        Args:
            user_id: The Matrix ID (@bob:example.org) of the user seeking permission.
            permission: The string ID representing the permission being sought.

        Returns:
            True if the rules allow the user to use that permission or no decision is made and not denied by default,
            False if the user is denied from using that permission.
        """
        if permission not in ALL_UNDERSTOOD_PERMISSIONS:
            raise ValueError(f"Permission not recognised: {permission!r}")

        for rule in self._config.rules:
            rule_result = rule.apply(user_id, permission)
            if rule_result == RuleResult.Allow:
                return True
            elif rule_result == RuleResult.Deny:
                return False

        if permission in self._config.default_deny:
            return False

        return True

    async def callback_user_may_create_room(self, user: str) -> bool:
        return self._apply_rules(user, CREATE_ROOM)

    async def callback_user_may_invite(
        self, inviter: str, invitee: str, room_id: str
    ) -> bool:
        return (
            self._apply_rules(inviter, INVITE)
            and (
                self._apply_rules(inviter, INVITE_ALL)
                or self._apply_rules(invitee, RECEIVE_INVITES)
            )
        )

    async def callback_user_may_join_room(self, user: str, room_id: str, is_invited: bool) -> bool:
        logger.info(f"Checking {user} for {room_id}, is_invited={is_invited}")
        try:
            state = await self._api.get_room_state(room_id)
            member_event = state.get(("m.room.member", user))
            if member_event and member_event["content"].get("membership") == "join":
                logger.info(f"{user} is joined, allowing action")
                return True
        except Exception as e:
            logger.warning(f"State check failed for {room_id}: {str(e)}")
    
        has_join_room = self._apply_rules(user, JOIN_ROOM)
        if has_join_room or is_invited:
            logger.info(f"Allowing join: has_join_room={has_join_room}, is_invited={is_invited}")
            return True
        logger.info(f"Denying join: has_join_room={has_join_room}, is_invited={is_invited}")
        return False
