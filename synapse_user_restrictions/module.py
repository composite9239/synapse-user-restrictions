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
from synapse.events import EventBase
from synapse.types import StateMap

from synapse_user_restrictions.config import (
    ALL_UNDERSTOOD_PERMISSIONS,
    CREATE_ROOM,
    INVITE,
    RECEIVE_INVITES,
    INVITE_ALL,
    JOIN_ROOM,
    LEAVE_ADMIN_ROOM,
    ConfigDict,
    RuleResult,
    UserRestrictionsModuleConfig,
)

class UserRestrictionsModule:
    def __init__(self, config: UserRestrictionsModuleConfig, api: ModuleApi):
        self._api = api
        self._config = config

        # Register spam checker callbacks
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
        If no rules make a decision, the permission will be allowed by default.

        Arguments:
            user_id: the Matrix ID (@bob:example.org) of the user seeking permission
            permission: the string ID representing the permission being sought

        Returns:
            True if the rules allow the user to use that permission or no decision is made,
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

    async def callback_user_may_invite(self, inviter: str, invitee: str, room_id: str) -> bool:
        return (
            self._apply_rules(inviter, INVITE)
            and (
                self._apply_rules(inviter, INVITE_ALL)
                or self._apply_rules(invitee, RECEIVE_INVITES)
            )
        )

    async def callback_user_may_join_room(self, user: str, room_id: str, is_invited: bool) -> bool:
        """
        Check if a user is allowed to join a room based on the join_room permission and invitation status.

        Args:
            user: The Matrix ID of the user attempting to join (e.g., "@alice:example.com").
            room_id: The ID of the room being joined.
            is_invited: Whether the user was invited to the room.

        Returns:
            True if the user can join the room (has join_room permission or is invited),
            False otherwise.
        """
        has_join_room = self._apply_rules(user, JOIN_ROOM)
        if has_join_room or is_invited:
            return True
        return False

    async def check_event_allowed(self, event: EventBase, state: StateMap[EventBase]) -> tuple[bool, None]:
        """
        Check if an event is allowed, specifically blocking users from leaving a room
        if the only other member is an admin and the user has leave_admin_room denied.

        Args:
            event: The event being checked.
            state: The current state of the room.

        Returns:
            (True, None) if the event is allowed, (False, None) if it should be blocked.
        """
        if event.type != "m.room.member" or event.membership != "leave":
            return True, None  # Only interested in leave events

        user_id = event.state_key  # The user leaving the room

        # Get current room members excluding the user leaving
        current_members = [
            state_key
            for (ev_type, state_key), ev in state.items()
            if ev_type == "m.room.member" and ev.membership == "join" and state_key != user_id
        ]

        # Check if the only other member is one of the configured admins
        admins = set(self._config.admins)
        if len(current_members) == 1 and current_members[0] in admins:
            # Check if the user has leave_admin_room denied
            if not self._apply_rules(user_id, LEAVE_ADMIN_ROOM):
                return False, None  # Block the leave event

        return True, None  # Allow the event
