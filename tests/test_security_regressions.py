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
import unittest

from phssh_security import quote_iptables_comment, quote_shell_argument, validate_iptables_protocol, validate_remote_ip


class SecurityRegressionTests(unittest.TestCase):
    def test_user_name_is_one_shell_argument(self) -> None:
        value = "user; touch /tmp/pwned"

        self.assertEqual(shlex.split(quote_shell_argument(value, "user_name")), [value])

    def test_protocol_rejects_non_allowlisted_values(self) -> None:
        for value in ["tcp; id", "-m", "", "setp"]:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "Invalid protocol"):
                validate_iptables_protocol(value)

    def test_remote_ip_accepts_addresses_and_networks(self) -> None:
        for value in ["192.0.2.5", "2001:db8::1", "192.0.2.0/24"]:
            with self.subTest(value=value):
                self.assertTrue(validate_remote_ip(value))

    def test_remote_ip_rejects_shell_and_hostname_input(self) -> None:
        for value in ["example.com", "192.0.2.1; id", "-j ACCEPT"]:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "Invalid remote_ip"):
                validate_remote_ip(value)

    def test_comment_is_one_shell_argument(self) -> None:
        value = "ticket'; touch /tmp/pwned; #"

        self.assertEqual(shlex.split(quote_iptables_comment(value)), [f"{value} -- Added by Phantom"])
