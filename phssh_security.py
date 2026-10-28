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

import base64
import shlex

import paramiko


IPTABLES_PROTOCOLS = frozenset({"all", "tcp", "udp", "udplite", "icmp", "esp", "ah", "sctp"})


def configure_host_key_verification(client, server, asset_key, action_key=None):
    """Pin a supplied public host key, or preserve legacy trust when none is supplied."""
    expected_key = action_key if action_key not in (None, "") else asset_key
    if expected_key is None or expected_key == "":
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return

    try:
        if not isinstance(expected_key, str) or "\n" in expected_key or "\r" in expected_key:
            raise ValueError("Expected one public host key")
        key_type, key_data, *_comment = expected_key.split()
        host_key = paramiko.PKey.from_type_string(key_type, base64.b64decode(key_data, validate=True))
    except Exception as e:
        raise ValueError("Invalid ssh_host_key. Use OpenSSH public-key format: <key-type> <base64-key> [comment]") from e

    client.get_host_keys().add(server, host_key.get_name(), host_key)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())


def quote_shell_argument(value, name):
    """Return one non-empty shell argument, safely quoted."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Invalid value for '{name}'")
    return shlex.quote(value)


def quote_iptables_chain(value):
    """Validate and quote an iptables chain name for a shell command."""
    if not isinstance(value, str) or not value:
        raise ValueError("Invalid chain. Provide a non-empty chain name")
    if len(value.encode()) >= 29:
        raise ValueError("Invalid chain. Chain names must be at most 28 bytes")
    if value[0] in {"-", "!"} or any(character.isspace() for character in value):
        raise ValueError("Invalid chain. Chain names cannot start with '-' or '!' or contain whitespace")
    return shlex.quote(value)


def validate_iptables_protocol(value):
    """Return an allowlisted iptables protocol."""
    if not isinstance(value, str) or value.strip().lower() not in IPTABLES_PROTOCOLS:
        raise ValueError("Invalid protocol. Use one of: ah, all, esp, icmp, sctp, tcp, udp, udplite")
    return value.strip().lower()


def quote_iptables_comment(value):
    """Build one safely quoted iptables comment argument."""
    suffix = "Added by Phantom"
    comment = f"{value} -- {suffix}" if value else suffix
    return shlex.quote(comment)
