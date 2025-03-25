# File: phssh_connector.py
#
# Copyright (c) 2016-2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom App imports
import os
import sys
import time
from contextlib import closing
from socket import gaierror as SocketError

import paramiko
import phantom.app as phantom
import phantom.rules as ph_rules
import simplejson as json
from paramiko.ssh_exception import AuthenticationException, BadHostKeyException
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault as Vault

# Import local
from phssh_consts import *


try:
    from urllib.parse import unquote
except Exception:
    from urllib import unquote

os.sys.path.insert(0, f"{os.path.dirname(os.path.abspath(__file__))}/paramikossh")


class SshConnector(BaseConnector):
    def __init__(self):
        super().__init__()

        self._ssh_client = None
        self._shell_channel = None
        self.OS_TYPE = OS_LINUX

    def _get_error_message_from_exception(self, e):
        """This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = SSH_CODE_UNAVAILABLE_ERR
        error_msg = SSH_MSG_UNAVAILABLE_ERR

        self.error_print(error_msg, dump_object=e)

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = SSH_CODE_UNAVAILABLE_ERR
                    error_msg = e.args[0]
        except Exception:
            pass

        return f"Error Code: {error_code}. Error Message: {error_msg}"

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        """This method is to check if the provided input parameter value
        is a non-zero positive integer and returns the integer value of the parameter itself.

        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: input parameter message key
        :allow_zero: whether zero should be considered as valid value or not
        :return: integer value of the parameter or None in case of failure
        """

        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, SSH_VALID_INT_MSG.format(param=key)), None

                parameter = int(parameter)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, SSH_VALID_INT_MSG.format(param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, SSH_NON_NEG_INT_MSG.format(param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, SSH_NON_NEG_NON_ZERO_INT_MSG.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

    def initialize(self):
        config = self.get_config()
        self._state = self.load_state()

        self._username = config[SSH_JSON_USERNAME]
        self._password = config.get(SSH_JSON_PASSWORD)
        self._root = config.get(SSH_JSON_ROOT, False)
        self._rsa_key_file = config.get(SSH_JSON_RSA_KEY)

        self._pseudo_terminal = config.get(SSH_JSON_PSEUDO_TERMINAL, False)
        self._disable_sha2 = config.get(SSH_JSON_DISABLE_SHA2, False)
        # integer validation for 'timeout' config parameter
        timeout = config.get(SSH_JSON_TIMEOUT)
        ret_val, self._timeout = self._validate_integer(self, timeout, SSH_JSON_TIMEOUT)
        if phantom.is_fail(ret_val):
            return self.get_status()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except Exception:
            return self.set_status(phantom.APP_ERROR, SSH_FETCHING_PYTHON_VERSION_MSG_ERR)

        return phantom.APP_SUCCESS

    def _start_connection(self, action_result, server):
        self.debug_print(f"PARAMIKO VERSION. {paramiko.__version__}")

        if self._rsa_key_file is None and self._password is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_PWD_OR_RSA_KEY_NOT_SPECIFIED_MSG_ERR)

        if self._rsa_key_file:
            try:
                if os.path.exists(self._rsa_key_file):
                    key = paramiko.RSAKey.from_private_key_file(self._rsa_key_file)
                else:
                    ssh_file_path1 = f"/home/phantom-worker/.ssh/{self._rsa_key_file}"
                    ssh_file_path2 = f"/home/phanru/.ssh/{self._rsa_key_file}"
                    if os.path.exists(ssh_file_path1):
                        key = paramiko.RSAKey.from_private_key_file(ssh_file_path1)
                    elif os.path.exists(ssh_file_path2):
                        key = paramiko.RSAKey.from_private_key_file(ssh_file_path2)
                    else:
                        raise Exception("No such file or directory")
                self._password = None

            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, f"{SSH_CONNECTIVITY_FAILED_ERR}. {err}")
        else:
            key = None

        self._ssh_client = paramiko.SSHClient()
        self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, server)
        try:
            if self._disable_sha2:
                self.debug_print("Disabling SHA2 algorithms")
                self._ssh_client.connect(
                    hostname=server,
                    username=self._username,
                    pkey=key,
                    password=self._password,
                    allow_agent=False,
                    look_for_keys=True,
                    timeout=FIRST_RECV_TIMEOUT,
                    disabled_algorithms=dict(pubkeys=["rsa-sha2-512", "rsa-sha2-256"]),
                )
            else:
                self._ssh_client.connect(
                    hostname=server,
                    username=self._username,
                    pkey=key,
                    password=self._password,
                    allow_agent=False,
                    look_for_keys=True,
                    timeout=FIRST_RECV_TIMEOUT,
                )
        except AuthenticationException:
            return action_result.set_status(phantom.APP_ERROR, SSH_AUTHENTICATION_FAILED_MSG_ERR)
        except BadHostKeyException as e:
            err = self._get_error_message_from_exception(e)
            error_msg = f"{SSH_BAD_HOST_KEY_MSG_ERR}. {err}"
            return action_result.set_status(phantom.APP_ERROR, error_msg)
        except SocketError:
            error_msg = f"{SSH_CONNECTIVITY_FAILED_ERR}. {SSH_FAILED_TO_RESOLVE_MSG_ERR.format(server=server)}"
            return action_result.set_status(phantom.APP_ERROR, error_msg)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, f"{SSH_CONNECTIVITY_FAILED_ERR}. {err}")

        return phantom.APP_SUCCESS

    def _send_command(self, command, action_result, passwd="", timeout=0, suppress=False):
        """
        Args:
            action_result:  object used to store the status
            command: command to send
            passwd:  password, if command needs to be run with root
            timeout: how long to wait before terminating program
            suppress: don't send message / heartbeat back to phantom
        """
        try:
            output = ""
            self.debug_print("Calling 'get_transport' via SSH client")
            trans = self._ssh_client.get_transport()

            self.debug_print("Creating session")
            self._shell_channel = trans.open_session()

            self._shell_channel.set_combine_stderr(True)
            if self._pseudo_terminal:
                self._shell_channel.get_pty()

            self.debug_print(f"Calling 'exec_command' for command: {command}")
            self._shell_channel.settimeout(SEND_TIMEOUT)
            self._shell_channel.exec_command(command)
            self.debug_print("Calling 'get_output' method for processing the output")
            ret_val, data, exit_status = self._get_output(action_result, timeout, passwd, suppress)
            output += data

            self.debug_print("Cleaning the output")
            output = self._clean_stdout(output, passwd)
            if phantom.is_fail(action_result.get_status()):
                return action_result.get_status(), output, exit_status
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, f"{SSH_SHELL_SEND_COMMAND_ERR.format(command)}. {err}"), None, None

        self.debug_print("Command executed successfully")
        return action_result.set_status(phantom.APP_SUCCESS, SSH_SUCCESS_CMD_EXEC), output, exit_status

    def _get_output(self, action_result, timeout, passwd, suppress):
        sendpw = True
        output = ""
        i = 1
        stime = int(time.time())
        if not suppress:
            self.save_progress("Executing command")
        try:
            while True:
                ctime = int(time.time())
                if timeout and ctime - stime >= timeout:
                    err = f"Error: Timeout after {timeout} seconds"
                    return action_result.set_status(phantom.APP_ERROR, err), output, 1
                elif self._shell_channel.recv_ready():
                    output += self._shell_channel.recv(8192).decode("utf-8")
                    # This is pretty messy but it's just the way it is I guess
                    if sendpw and passwd:
                        try:
                            self._shell_channel.send(f"{passwd}\n")
                            if not self._pseudo_terminal:
                                output += "\n"
                        except OSError:
                            pass
                        sendpw = False
                # Exit status AND nothing left in output
                elif self._shell_channel.exit_status_ready() and not self._shell_channel.recv_ready():
                    break
                else:
                    time.sleep(1)
                    if not suppress:
                        self.send_progress("Executing command" + "." * i)
                        i = i % 5 + 1
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err), "", None

        return action_result.set_status(phantom.APP_SUCCESS), output, self._shell_channel.recv_exit_status()

    def _clean_stdout(self, stdout, passwd):
        if stdout is None:
            return None

        try:
            lines = []
            for index, line in enumerate(stdout.splitlines()):
                if (passwd and passwd in line) or ("[sudo] password for" in line):
                    if passwd and passwd in line:
                        self.debug_print(f"Password found at index: {index}")
                    continue
                lines.append(line)
        except Exception:
            return None

        return "\n".join(lines)

    def _output_for_exit_status(self, action_result, exit_status, output_on_err, output_on_succ):
        # Shell returned an error
        if exit_status:
            action_result.set_status(phantom.APP_ERROR, output_on_err)
            d = {"output": output_on_err}
        else:
            action_result.set_status(phantom.APP_SUCCESS, SSH_SUCCESS_CMD_SUCCESS)
            d = {"output": output_on_succ}

        action_result.add_data(d)
        action_result.update_summary({"exit_status": exit_status})
        # result.add_data({"exit_status": exit_status})

        return action_result

    def _test_connectivity(self, param):
        self.save_progress("Testing SSH Connection")
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            endpoint = self.get_config()[SSH_JSON_DEVICE]
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, SSH_HOSTNAME_OR_IP_NOT_SPECIFIED_MSG_ERR)

        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            self.save_progress(SSH_CONNECTIVITY_TEST_ERR)
            return action_result.get_status()
        self.save_progress(SSH_CONNECTIVITY_ESTABLISHED)
        self.save_progress("Executing 'uname' command...")

        # Get Linux Distribution
        cmd = "uname -a"
        status_code, stdout, exit_status = self._send_command(cmd, action_result, suppress=True, timeout=self._timeout)

        # Couldn't send command
        if phantom.is_fail(status_code):
            return status_code

        # Some version of mac
        if exit_status == 0 and stdout.split()[0] == "Darwin":
            self.OS_TYPE = OS_MAC
        self.debug_print(f"ssh uname {stdout}")

        self.save_progress(SSH_SUCCESS_CONNECTIVITY_TEST)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ssh_execute_command(self, param):
        self.debug_print("Starting 'execute program' action function")

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]

        self.debug_print("Calling 'start_connection'..")
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTIVITY_ESTABLISHED)

        # As it turns out, even if the data type is "numeric" in the json
        # the data will end up being a string after you receive it

        # integer validation for 'timeout' action parameter
        timeout = param.get(SSH_JSON_TIMEOUT)
        if timeout is not None:
            ret_val, timeout = self._validate_integer(action_result, timeout, SSH_JSON_TIMEOUT, False)
            if phantom.is_fail(ret_val):
                timeout = self._timeout
                self.debug_print(f"Invalid value provided in the timeout parameter of the execute program action. {SSH_ASSET_TIMEOUT_MSG}")
        else:
            timeout = self._timeout
            self.debug_print(f"No value found in the timeout parameter of the execute program action. {SSH_ASSET_TIMEOUT_MSG}")

        script_file = param.get(SSH_JSON_SCRIPT_FILE)
        if script_file:
            try:
                with open(script_file) as f:
                    cmd = f.read()
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                err_msg = f"{SSH_UNABLE_TO_READ_SCRIPT_FILE_MSG_ERR.format(script_file=script_file)}. {err}"
                return action_result.set_status(phantom.APP_ERROR, err_msg)
        else:
            cmd = param.get(SSH_JSON_CMD)
            if not cmd:
                return action_result.set_status(phantom.APP_ERROR, SSH_COMMAND_OR_SCRIPT_FILE_NOT_PROVIDED_MSG_ERR)

        # Command needs to be run as root
        if not self._root and cmd.split()[0] == "sudo":
            passwd = self._password
            if passwd is None:
                return action_result.set_status(phantom.APP_ERROR, SSH_NEED_PW_FOR_ROOT_ERR)
        else:
            passwd = ""

        self.debug_print("Sending command for execution")
        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=timeout)

        # If command failed to send
        if phantom.is_fail(status_code):
            action_result.add_data({"output": stdout})
            return action_result.get_status()

        action_result = self._output_for_exit_status(action_result, exit_status, stdout, stdout)

        self.debug_print("'exec_command' action executed successfully")
        return action_result.get_status()

    def _handle_ssh_reboot_server(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTIVITY_ESTABLISHED)

        cmd = "sudo -S shutdown -r now"
        passwd = self._password
        root = self._root
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_NEED_PW_FOR_ROOT_ERR)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        # If command failed to send
        if phantom.is_fail(status_code):
            return action_result.get_status()

        # no exit status code is returned, in case the server is successfully rebooted
        if exit_status == -1:
            action_result.set_status(phantom.APP_SUCCESS, f"Exit status: {exit_status}. {SSH_VERIFY_LAST_REBOOT_TIME_MSG}")
            d = {"output": stdout}
        # Shell returned an error
        elif exit_status:
            action_result.set_status(phantom.APP_ERROR, stdout)
            d = {"output": stdout}
        else:
            action_result.set_status(phantom.APP_SUCCESS, SSH_SUCCESS_CMD_SUCCESS)
            d = {"output": SSH_SHELL_NO_ERR}

        action_result.add_data(d)
        action_result.update_summary({"exit_status": exit_status})

        return action_result.get_status()

    def _handle_ssh_shutdown_server(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTIVITY_ESTABLISHED)

        cmd = "sudo -S shutdown -h now"
        passwd = self._password
        root = self._root
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_NEED_PW_FOR_ROOT_ERR)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        # If command failed to send
        if phantom.is_fail(status_code):
            return action_result.get_status()

        # verifying whether the endpoint has successfully shutdown or not
        time.sleep(15)
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            d = {"output": SSH_SHELL_NO_ERR}
            action_result.add_data(d)
            action_result.update_summary({"exit_status": exit_status})
            return action_result.set_status(phantom.APP_SUCCESS, f"{SSH_ENDPOINT_SHUTDOWN_MSG}. {SSH_SUCCESS_CMD_SUCCESS}")

        action_result = self._output_for_exit_status(action_result, exit_status, stdout, SSH_SHELL_NO_ERR)

        return action_result.get_status()

    def _handle_ssh_list_processes(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTIVITY_ESTABLISHED)

        # excl_root = param.get(SSH_JSON_EXCL_ROOT, False)

        # ps on mac will always show the full username, ps on linux will
        #  only show usernames of <= 8 characters unless otherwise specified
        fuser = "" if self.OS_TYPE == OS_MAC else ":32"
        cmd = f"ps c -Ao user{fuser},uid,pid,ppid,stime,command"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        action_result = self._parse_processes(action_result, stdout, cmd)
        # action_result.update_summary({"exit_status": exit_status})

        return action_result.get_status()

    def _parse_processes(self, action_result, stdout, cmd):
        """
        STDOUT:
        USER  UID  PID  PPID  STIME  CMD
        """
        try:
            ll = []  # List to store dictionaries
            headers = stdout.splitlines()[0].split()
            rows = stdout.splitlines()
            for row in rows[1:]:
                r = row.split()
                d = {}  # Used to store results
                for i in range(0, len(headers)):
                    if i == len(headers) - 1:
                        d[headers[i].lower()] = " ".join(r[i:])
                    else:
                        d[headers[i].lower()] = r[i]
                ll.append(d.copy())

            action_result.add_data({"processes": ll})
            action_result.update_summary({"total_processes": len(ll)})

            # result.set_status(phantom.APP_SUCCESS, SSH_SUCCESS_CMD_SUCCESS)
            action_result.set_status(phantom.APP_SUCCESS)
        except Exception:
            action_result.set_status(phantom.APP_ERROR, SSH_UNABLE_TO_PARSE_OUTPUT_OF_CMD.format(cmd))

        return action_result

    def _handle_ssh_kill_process(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTIVITY_ESTABLISHED)

        pid = param[SSH_JSON_PID]

        # integer validation for 'pid' action parameter
        ret_val, pid = self._validate_integer(action_result, pid, SSH_JSON_PID, True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        passwd = self._password
        root = self._root
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_NEED_PW_FOR_ROOT_ERR)
        cmd = f"sudo -S kill -SIGKILL {pid}"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        action_result = self._output_for_exit_status(action_result, exit_status, stdout, SSH_PID_TERMINATED_MSG.format(pid=pid))

        return action_result.get_status()

    def _handle_ssh_logout_user(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTIVITY_ESTABLISHED)

        user_name = param[SSH_JSON_USER]
        passwd = self._password
        root = self._root
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_NEED_PW_FOR_ROOT_ERR)
        cmd = f"sudo -S pkill -SIGKILL -u {user_name}"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        action_result = self._output_for_exit_status(action_result, exit_status, stdout, SSH_LOGOFF_USER_MSG.format(username=user_name))

        return action_result.get_status()

    def _handle_ssh_list_conn(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTIVITY_ESTABLISHED)

        passwd = self._password
        root = self._root
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_NEED_PW_FOR_ROOT_ERR)
        local_addr = param.get(SSH_JSON_LOCAL_ADDR, "")
        local_port = param.get(SSH_JSON_LOCAL_PORT, "")

        # integer validation for 'local_port' action parameter
        if local_port:
            ret_val, local_port = self._validate_integer(action_result, local_port, SSH_JSON_LOCAL_PORT)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        local_port = str(local_port)

        remote_addr = param.get(SSH_JSON_REMOTE_ADDR, "")
        remote_port = param.get(SSH_JSON_REMOTE_PORT, "")

        # integer validation for 'remote_port' action parameter
        if remote_port:
            ret_val, remote_port = self._validate_integer(action_result, remote_port, SSH_JSON_REMOTE_PORT)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        remote_port = str(remote_port)

        # Macs have BSD netstat which doesn't give enough information
        if self.OS_TYPE == OS_MAC:
            return self._list_connections_mac(param, action_result, passwd, local_addr, local_port, remote_addr, remote_port)

        cmd = "sudo -S netstat -etnp"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        action_result.update_summary({"exit_status": exit_status})
        if exit_status:
            action_result.add_data({"output": stdout})
            if not stdout:
                return action_result.set_status(phantom.APP_ERROR, f"{SSH_NO_SHELL_OUTPUT_MSG_ERR}. {SSH_IS_NETSTAT_INSTALLED_MSG}")
            return action_result.set_status(
                phantom.APP_ERROR, f"{SSH_SHELL_OUTPUT_MSG_ERR.format(stdout=stdout)}. {SSH_IS_NETSTAT_INSTALLED_MSG}"
            )

        action_result = self._parse_connections(action_result, stdout, cmd, local_addr, local_port, remote_addr, remote_port)

        return action_result.get_status()

    def _parse_connections(self, action_result, stdout, cmd, la, lp, ra, rp):
        """Process output for connections
        PROTO Rec-Q Send-Q Local_Address Foreign_Address State User Inode Pid/Program_Name
        """
        try:
            ll = []  # List to store dictionaries
            rows = stdout.splitlines()

            # if (len(rows) <= 1):
            #     return None

            for row in rows[2:]:  # Don't parse first two lines
                r = row.split()
                d = {}
                d["protocol"] = r[0]
                d["rec_q"] = r[1]
                d["send_q"] = r[2]
                try:
                    s = r[3].split(":")
                    d["local_port"] = s[-1]
                    if lp and d["local_port"] != lp:
                        continue
                    del s[-1]
                    d["local_ip"] = ":".join(s)
                    if la and d["local_ip"] != la:
                        continue
                except Exception:  # Some error parsing
                    d["local_port"] = ""
                    d["local_ip"] = ""
                try:
                    s = r[4].split(":")
                    d["remote_port"] = s[-1]
                    if rp and d["remote_port"] != rp:
                        continue
                    del s[-1]
                    d["remote_ip"] = ":".join(s)
                    if ra and d["remote_ip"] != ra:
                        continue
                except Exception:  # Some error parsing
                    d["remote_port"] = ""
                    d["remote_ip"] = ""
                d["state"] = r[5]
                d["uid"] = r[6]
                d["inode"] = r[7]
                try:
                    if r[8] == "-":
                        d["pid"] = ""
                        d["cmd"] = ""
                    else:
                        s = r[8].split("/")
                        d["pid"] = s[0]
                        del s[0]
                        d["cmd"] = "/".join(s)
                except Exception:
                    d["pid"] = ""
                    d["cmd"] = ""
                ll.append(d.copy())

            action_result.add_data({"connections": ll})

            action_result.set_status(phantom.APP_SUCCESS, SSH_SUCCESS_CMD_SUCCESS)
        except Exception:
            action_result.set_status(phantom.APP_ERROR, SSH_UNABLE_TO_PARSE_OUTPUT_OF_CMD.format(cmd))

        return action_result

    def _list_connections_mac(self, param, action_result, passwd, local_addr, local_port, remote_addr, remote_port):
        cmd = "sudo -S lsof -nP -i"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        action_result.update_summary({"exit_status": exit_status})
        if exit_status:
            action_result.add_data({"output": stdout})
            if not stdout:
                return action_result.set_status(phantom.APP_ERROR, SSH_NO_SHELL_OUTPUT_MSG_ERR)
            return action_result.set_status(phantom.APP_ERROR, SSH_SHELL_OUTPUT_MSG_ERR.format(stdout=stdout))

        action_result = self._parse_connections_mac(action_result, stdout, cmd, local_addr, local_port, remote_addr, remote_port)

        return action_result.get_status()

    def _parse_connections_mac(self, action_result, stdout, cmd, la, lp, ra, rp):
        """Process output for connections
        COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME (STATE)?
        """
        try:
            ll = []  # List to store dictionaries
            rows = stdout.splitlines()

            if len(rows) <= 1:
                return None

            for row in rows[1:]:  # Skip the first line
                r = row.split()
                d = {}
                d["cmd"] = r[0]
                d["pid"] = r[1]
                d["uid"] = r[2]
                d["fd"] = r[3]
                d["type"] = r[4]
                d["device"] = r[5]
                d["sizeoff"] = r[6]
                d["protocol"] = r[7]
                n = r[8].split("->")
                if len(n) == 2:
                    # Get Local
                    s = n[0].split(":")
                    d["local_port"] = s[-1]
                    if lp and d["local_port"] != lp:
                        continue
                    del s[-1]
                    d["local_ip"] = ":".join(s)
                    if la and d["local_ip"] != la:
                        continue
                    # Get Remote
                    s = n[1].split(":")
                    d["remote_port"] = s[-1]
                    if rp and d["remote_port"] != rp:
                        continue
                    del s[-1]
                    d["remote_ip"] = ":".join(s)
                    if ra and d["remote_ip"] != ra:
                        continue
                else:
                    # If there is no remote connection (as many things will display),
                    #  and they are being filtered, don't add
                    if rp or ra:
                        continue
                    s = n[0].split(":")
                    d["local_port"] = s[-1]
                    if lp and d["local_port"] != lp:
                        continue
                    del s[-1]
                    d["local_ip"] = ":".join(s)
                    if la and d["local_ip"] != la:
                        continue
                    d["remote_port"] = ""
                    d["remote_ip"] = ""
                try:
                    d["state"] = r[9][1:-1]  # Ignore paranthesis
                except Exception:
                    d["state"] = ""
                ll.append(d.copy())

            action_result.add_data({"connections": ll})

            action_result.set_status(phantom.APP_SUCCESS, SSH_SUCCESS_CMD_SUCCESS)
        except Exception:
            action_result.set_status(phantom.APP_ERROR, SSH_UNABLE_TO_PARSE_OUTPUT_OF_CMD.format(cmd))

        return action_result

    def _handle_ssh_list_fw_rules(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTIVITY_ESTABLISHED)

        if self.OS_TYPE == OS_MAC:
            return action_result.set_status(phantom.APP_ERROR, SSH_FIREWALL_CMDS_NOT_SUPPORTED_ERR)

        passwd = self._password
        root = self._root
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_NEED_PW_FOR_ROOT_ERR)
        prot = param.get(SSH_JSON_PROTOCOL, "")
        port = param.get(SSH_JSON_PORT, "")

        # integer validation of 'port' action parameter
        if port:
            ret_val, port = self._validate_integer(action_result, port, SSH_JSON_PORT)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
        port = str(port)
        chain = param.get(SSH_JSON_CHAIN, "")

        cmd = f"sudo -S iptables -L {chain} --line-numbers -n"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        action_result.update_summary({"exit_status": exit_status})
        if exit_status:
            action_result.add_data({"output": stdout})
            if not stdout:
                return action_result.set_status(phantom.APP_ERROR, SSH_NO_SHELL_OUTPUT_MSG_ERR)
            return action_result.set_status(phantom.APP_ERROR, SSH_SHELL_OUTPUT_MSG_ERR.format(stdout=stdout))

        action_result = self._filter_fw_rules(action_result, stdout, cmd, prot, port)

        return action_result.get_status()

    def _filter_fw_rules(self, action_result, stdout, cmd, prot, port):
        try:
            ll = []
            cur_chain = ""
            d = {}
            rows = stdout.splitlines()

            i = 0
            while i < len(rows):
                cur_chain = rows[i].split()[1]  # Name of chain
                i += 2  # Skip header row
                while i < len(rows):
                    if rows[i] == "":
                        i += 1
                        break  # New Chain
                    row = rows[i].split()
                    if len(row) >= 6:  # This is hopefully always true
                        d["chain"] = cur_chain
                        d["num"] = row[0]
                        d["target"] = row[1]
                        if prot and row[2] != prot:
                            i += 1
                            continue
                        d["protocol"] = row[2]
                        d["source"] = row[4]
                        d["destination"] = row[5]
                        try:  # the rest can contain port numbers, comments, and other things
                            the_rest = " ".join(row[6:])
                        except Exception:
                            the_rest = ""
                        if port and port not in the_rest:
                            i += 1
                            continue
                        d["options"] = the_rest
                        ll.append(d.copy())
                    i += 1

            action_result.add_data({"rules": ll})
            action_result.set_status(phantom.APP_SUCCESS, SSH_SUCCESS_CMD_SUCCESS)
        except Exception:
            action_result.set_status(phantom.APP_ERROR, SSH_UNABLE_TO_PARSE_OUTPUT_OF_CMD.format(cmd))

        return action_result

    def _handle_ssh_block_ip(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTIVITY_ESTABLISHED)

        if self.OS_TYPE == OS_MAC:
            return action_result.set_status(phantom.APP_ERROR, SSH_FIREWALL_CMDS_NOT_SUPPORTED_ERR)

        no_ip = True
        no_port = True
        passwd = self._password
        root = self._root
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_NEED_PW_FOR_ROOT_ERR)

        protocol = param[SSH_JSON_PROTOCOL]
        direction = "INPUT" if param[SSH_JSON_DIRECTION].lower() == "in" else "OUTPUT"

        remote_ip = param.get(SSH_JSON_REMOTE_IP)
        if remote_ip:
            if direction == "INPUT":
                remote_ip = f"-s {remote_ip}"
            else:
                remote_ip = f"-d {remote_ip}"
            no_ip = False
        else:
            remote_ip = ""

        remote_port = param.get(SSH_JSON_REMOTE_PORT)

        # integer validation of 'remote_port' action parameter
        ret_val, remote_port = self._validate_integer(action_result, remote_port, SSH_JSON_REMOTE_PORT, True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if remote_port:
            if direction == "INPUT":
                port = f"--destination-port {remote_port}"
            else:
                port = f"-dport {remote_port}"
            no_port = False
        else:
            port = ""

        user_comment = param.get(SSH_JSON_COMMENT)
        if user_comment:
            comment = f"-m comment --comment '{user_comment} -- Added by Phantom'"
        else:
            comment = "-m comment --comment 'Added by Phantom'"

        if no_ip and no_port:
            return action_result.set_status(phantom.APP_ERROR, SSH_REMOTE_IP_OR_PORT_NOT_SPECIFIED_MSG_ERR)

        cmd = f"sudo -S iptables -I {direction} -p {protocol} {remote_ip} {port} -j DROP {comment}"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        if exit_status:
            action_result.add_data({"output": stdout})
            if not stdout:
                return action_result.set_status(phantom.APP_ERROR, SSH_NO_SHELL_OUTPUT_MSG_ERR)
            return action_result.set_status(phantom.APP_ERROR, SSH_SHELL_OUTPUT_MSG_ERR.format(stdout=stdout))

        action_result = self._save_iptables(action_result, passwd)

        return action_result.get_status()

    def _handle_ssh_delete_fw_rule(self, param):
        """Should this be changed to only delete rules
        created by Phantom?
        """
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTIVITY_ESTABLISHED)

        if self.OS_TYPE == OS_MAC:
            return action_result.set_status(phantom.APP_ERROR, SSH_FIREWALL_CMDS_NOT_SUPPORTED_ERR)

        passwd = self._password
        root = self._root
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_NEED_PW_FOR_ROOT_ERR)
        chain = param[SSH_JSON_CHAIN]
        number = param[SSH_JSON_NUMBER]

        # integer validation for 'number' action parameter
        ret_val, number = self._validate_integer(action_result, number, SSH_JSON_NUMBER, True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        cmd = f"sudo -S iptables -D {chain} {number}"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        if exit_status:
            action_result.add_data({"output": stdout})
            if not stdout:
                return action_result.set_status(phantom.APP_ERROR, SSH_NO_SHELL_OUTPUT_MSG_ERR)
            return action_result.set_status(phantom.APP_ERROR, SSH_SHELL_OUTPUT_MSG_ERR.format(stdout=stdout))

        action_result = self._save_iptables(action_result, passwd)

        return action_result.get_status()

    def _save_iptables(self, action_result, passwd):
        """iptables needs to be saved after a command modifies it"""
        cmd = "sudo -S service iptables save"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result

        action_result = self._output_for_exit_status(action_result, exit_status, f"{stdout} Is the iptables service running?", SSH_SHELL_NO_ERR)

        return action_result

    def _handle_ssh_get_file(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTIVITY_ESTABLISHED)

        file_path = param[SSH_JSON_FILE_PATH]
        file_path_ascii = bytes(file_path, "utf-8")
        # /some/dir/file_name
        file_name = file_path.split("/")[-1]
        if hasattr(Vault, "get_vault_tmp_dir"):
            vault_path = f"{Vault.get_vault_tmp_dir()}/{file_name}"
        else:
            vault_path = f"/vault/tmp/{file_name}"

        with closing(self._ssh_client.open_sftp()) as sftp:
            try:
                sftp.get(file_path_ascii, vault_path)
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, SSH_GET_FILE_MSG_ERR.format(err=err))

        vault_ret = Vault.add_attachment(vault_path, self.get_container_id(), file_name=file_name)
        if vault_ret.get("succeeded"):
            action_result.set_status(phantom.APP_SUCCESS, "Transferred file")
            summary = {
                phantom.APP_JSON_VAULT_ID: vault_ret[phantom.APP_JSON_HASH],
                phantom.APP_JSON_NAME: file_name,
                phantom.APP_JSON_SIZE: vault_ret.get(phantom.APP_JSON_SIZE),
            }
            action_result.update_summary(summary)
        else:
            action_result.set_status(phantom.APP_ERROR, f"Failed to add file to vault: {vault_ret.get('message', 'unknown error')}")

        return action_result.get_status()

    def _handle_ssh_put_file(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTIVITY_ESTABLISHED)

        # fetching phantom vault details
        try:
            success, message, vault_meta_info = ph_rules.vault_info(vault_id=param[SSH_JSON_VAULT_ID])
            vault_meta_info = list(vault_meta_info)
            if not success or not vault_meta_info:
                error_msg = f" Error Details: {unquote(message)}" if message else ""
                return action_result.set_status(phantom.APP_ERROR, f"{SSH_UNABLE_TO_RETREIVE_VAULT_ITEM_MSG_ERR}.{error_msg}")
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, f"{SSH_UNABLE_TO_RETREIVE_VAULT_ITEM_MSG_ERR}. {err}")

        # phantom vault file path
        file_path = vault_meta_info[0].get("path")

        # phantom vault file name
        dest_file_name = vault_meta_info[0].get("name")
        file_dest = param[SSH_JSON_FILE_DEST]

        # Returning an error if the filename is included in the file_destination path
        if dest_file_name in file_dest:
            return action_result.set_status(phantom.APP_ERROR, SSH_EXCLUDE_FILENAME_MSG_ERR)

        destination_path = "{}{}{}".format(param[SSH_JSON_FILE_DEST], "/" if param[SSH_JSON_FILE_DEST][-1] != "/" else "", dest_file_name)

        sftp = self._ssh_client.open_sftp()
        try:
            sftp.put(file_path, destination_path)
        except FileNotFoundError as e:
            err = self._get_error_message_from_exception(e)
            sftp.close()
            err = f"{err}. {SSH_FILE_NOT_FOUND_MSG_ERR}"
            return action_result.set_status(phantom.APP_ERROR, SSH_PUT_FILE_MSG_ERR.format(err=err))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            sftp.close()
            return action_result.set_status(phantom.APP_ERROR, SSH_PUT_FILE_MSG_ERR.format(err=err))
        sftp.close()

        summary = {"file_sent": destination_path}
        action_result.update_summary(summary)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _mb_to_gb(self, mb_val):
        if mb_val.isnumeric():
            gb_val = float(mb_val) / 1024
            if gb_val < 1:
                return f"{mb_val}M"
            return f"{gb_val:.2f}G"
        else:
            return mb_val

    def _parse_generic(self, data=None, headers=None, newline="\n", best_fit=True, new_header_names=None, action_result=None):
        # header_locator should be a list of the headers returned in the results
        # ie for df -hP, this would be ['Filesystem', 'Size', 'Used', 'Avail', 'Use%', 'Mounted on']
        # if best_fit is True, all rows are expected to have the same number of columns as headers.
        # if best_fit is False, best attempts to fill data will be made
        # new header names will be used in the output in place of the headers= fields.
        results = []
        for line in data.split(newline):
            found_header = False
            for header in headers:
                if header in line and header != "":
                    found_header = True
                    break
            #
            temp = {}
            #
            if found_header:
                continue
            elif len(line.split()) == 0:
                continue
            elif best_fit and len(line.split()) != len(headers):
                temp["error_message"] = SSH_PARSE_HEADER_ERR.format(len(headers), headers, len(line), line)
                continue

            if best_fit:
                for num, val in enumerate(line.strip().split()):
                    if headers[num] == "":
                        continue
                    else:
                        if new_header_names:
                            temp[new_header_names[num]] = self._mb_to_gb(val)
                        else:
                            temp[headers[num]] = self._mb_to_gb(val)
            else:
                for num in range(0, len(headers)):
                    linedata = line.strip().split()
                    if new_header_names:
                        if new_header_names[num] == "" and headers[num] == "":
                            continue
                    elif headers[num] == "":
                        continue
                    if new_header_names:
                        try:
                            temp[new_header_names[num]] = self._mb_to_gb(linedata[num])
                        except Exception:
                            temp[new_header_names[num]] = ""
                    else:
                        try:
                            temp[headers[num]] = self._mb_to_gb(linedata[num])
                        except Exception:
                            temp[headers[num]] = ""
            temp["raw"] = line
            results.append(temp)
        return results

    def _handle_get_disk_usage(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTIVITY_ESTABLISHED)

        passwd = self._password
        root = self._root
        if root:
            passwd = None

        cmd = "df -hP"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        if exit_status:
            action_result.add_data({"output": stdout})
            if not stdout:
                return action_result.set_status(phantom.APP_ERROR, SSH_NO_SHELL_OUTPUT_MSG_ERR)
            return action_result.set_status(phantom.APP_ERROR, SSH_SHELL_OUTPUT_MSG_ERR.format(stdout=stdout))

        stdout2 = stdout.replace("%", "")  # clean up % from text
        result = self._parse_generic(data=stdout2, headers=["Filesystem", "Size", "Used", "Avail", "Use%", "Mounted on"], newline="\n")
        action_result.add_data(result)
        action_result.update_summary({"exit_status": exit_status})

        return action_result.get_status()

    def _handle_get_memory_usage(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTIVITY_ESTABLISHED)

        passwd = self._password
        root = self._root
        if root:
            passwd = None

        cmd = "free -m -l"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        if exit_status:
            action_result.add_data({"output": stdout})
            if not stdout:
                return action_result.set_status(phantom.APP_ERROR, SSH_NO_SHELL_OUTPUT_MSG_ERR)
            return action_result.set_status(phantom.APP_ERROR, SSH_SHELL_OUTPUT_MSG_ERR.format(stdout=stdout))

        result = self._parse_generic(
            data=stdout,
            headers=["", "total", "used", "free", "shared", "buff/cache", "available"],
            newline="\n",
            best_fit=False,
            new_header_names=["Type", "Total", "Used", "Free", "Shared", "Buff/Cache", "Available"],
        )
        action_result.add_data(result)
        action_result.update_summary({"exit_status": exit_status})

        return action_result.get_status()

    def finalize(self):
        # Close shh client
        if self._ssh_client:
            self._ssh_client.close()

        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity(param)
        elif action_id == ACTION_ID_EXEC_COMMAND:
            ret_val = self._handle_ssh_execute_command(param)
        elif action_id == ACTION_ID_REBOOT_SERVER:
            ret_val = self._handle_ssh_reboot_server(param)
        elif action_id == ACTION_ID_SHUTDOWN_SERVER:
            ret_val = self._handle_ssh_shutdown_server(param)
        elif action_id == ACTION_ID_LIST_PROCESSES:
            ret_val = self._handle_ssh_list_processes(param)
        elif action_id == ACTION_ID_TERMINATE_PROCESS:
            ret_val = self._handle_ssh_kill_process(param)
        elif action_id == ACTION_ID_LOGOUT_USER:
            ret_val = self._handle_ssh_logout_user(param)
        elif action_id == ACTION_ID_LIST_CONNECTIVITY:
            ret_val = self._handle_ssh_list_conn(param)
        elif action_id == ACTION_ID_LIST_FW_RULES:
            ret_val = self._handle_ssh_list_fw_rules(param)
        elif action_id == ACTION_ID_BLOCK_IP:
            ret_val = self._handle_ssh_block_ip(param)
        elif action_id == ACTION_ID_DELETE_FW_RULE:
            ret_val = self._handle_ssh_delete_fw_rule(param)
        elif action_id == ACTION_ID_GET_FILE:
            ret_val = self._handle_ssh_get_file(param)
        elif action_id == ACTION_ID_GET_MEMORY_USAGE:
            ret_val = self._handle_get_memory_usage(param)
        elif action_id == ACTION_ID_GET_DISK_USAGE:
            ret_val = self._handle_get_disk_usage(param)
        elif action_id == ACTION_ID_PUT_FILE:
            ret_val = self._handle_ssh_put_file(param)

        return ret_val


if __name__ == "__main__":
    import pudb

    pudb.set_trace()

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SshConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
