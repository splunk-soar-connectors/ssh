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


IPTABLES_PROTOCOLS = frozenset({"all", "tcp", "udp", "udplite", "icmp", "esp", "ah", "sctp"})


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
