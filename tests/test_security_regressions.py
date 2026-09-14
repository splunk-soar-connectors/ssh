# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import shlex

import pytest

from phssh_security import quote_iptables_comment, quote_shell_argument, validate_iptables_protocol, validate_remote_ip


def test_user_name_is_one_shell_argument() -> None:
    value = "user; touch /tmp/pwned"

    assert shlex.split(quote_shell_argument(value, "user_name")) == [value]


@pytest.mark.parametrize("value", ["tcp; id", "-m", "", "setp"])
def test_protocol_rejects_non_allowlisted_values(value: str) -> None:
    with pytest.raises(ValueError, match="Invalid protocol"):
        validate_iptables_protocol(value)


@pytest.mark.parametrize("value", ["192.0.2.5", "2001:db8::1", "192.0.2.0/24"])
def test_remote_ip_accepts_addresses_and_networks(value: str) -> None:
    assert validate_remote_ip(value)


@pytest.mark.parametrize("value", ["example.com", "192.0.2.1; id", "-j ACCEPT"])
def test_remote_ip_rejects_shell_and_hostname_input(value: str) -> None:
    with pytest.raises(ValueError, match="Invalid remote_ip"):
        validate_remote_ip(value)


def test_comment_is_one_shell_argument() -> None:
    value = "ticket'; touch /tmp/pwned; #"

    assert shlex.split(quote_iptables_comment(value)) == [f"{value} -- Added by Phantom"]
