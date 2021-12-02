# File: phssh_connector.py
#
# Copyright (c) 2016-2021 Splunk Inc.
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
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault as Vault
import phantom.rules as ph_rules

# Import local
from phssh_consts import *

import socket
import sys
import simplejson as json
import time
from bs4 import UnicodeDammit

import os
import paramiko
from socket import gaierror as SocketError
from paramiko.ssh_exception import BadHostKeyException
from paramiko.ssh_exception import AuthenticationException

try:
    from urllib.parse import unquote
except:
    from urllib import unquote

os.sys.path.insert(0, "{}/paramikossh".format(os.path.dirname(os.path.abspath(__file__))))


class SshConnector(BaseConnector):

    def __init__(self):
        super(SshConnector, self).__init__()

        self._ssh_client = None
        self._shell_channel = None
        self.OS_TYPE = OS_LINUX

    def _handle_py_ver_compat_for_input_str(self, input_str, always_encode=False):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :param always_encode: Used if the string needs to be encoded for python 3
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str is not None and (self._python_version == 2 or always_encode):
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print(SSH_PY_2TO3_ERR_MSG)

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = SSH_ERR_CODE_UNAVAILABLE
        error_msg = SSH_ERR_MSG_UNAVAILABLE

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = SSH_ERR_CODE_UNAVAILABLE
                    error_msg = e.args[0]
        except:
            pass

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = SSH_UNICODE_DAMMIT_TYPE_ERR_MSG
        except:
            error_msg = SSH_ERR_MSG_UNAVAILABLE

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        """ This method is to check if the provided input parameter value
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
            except:
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

        # integer validation for 'timeout' config parameter
        timeout = config.get(SSH_JSON_TIMEOUT)
        ret_val, self._timeout = self._validate_integer(self, timeout, SSH_JSON_TIMEOUT)
        if phantom.is_fail(ret_val):
            return self.get_status()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, SSH_ERR_FETCHING_PYTHON_VERSION_MSG)

        return phantom.APP_SUCCESS

    def _start_connection(self, action_result, server):

        self.debug_print("PARAMIKO VERSION. {}".format(paramiko.__version__))

        if self._rsa_key_file is None and self._password is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_PWD_OR_RSA_KEY_NOT_SPECIFIED_ERR_MSG)

        if self._rsa_key_file:
            try:
                if os.path.exists(self._rsa_key_file):
                    key = paramiko.RSAKey.from_private_key_file(self._rsa_key_file)
                else:
                    ssh_file_path1 = "/home/phantom-worker/.ssh/{}".format(self._rsa_key_file)
                    ssh_file_path2 = "/home/phanru/.ssh/{}".format(self._rsa_key_file)
                    if os.path.exists(ssh_file_path1):
                        key = paramiko.RSAKey.from_private_key_file(ssh_file_path1)
                    elif os.path.exists(ssh_file_path2):
                        key = paramiko.RSAKey.from_private_key_file(ssh_file_path2)
                    else:
                        raise Exception('No such file or directory')
                self._password = None

            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(SSH_ERR_CONNECTION_FAILED, err))
        else:
            key = None

        self._ssh_client = paramiko.SSHClient()
        self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, server)
        try:
            self._ssh_client.connect(hostname=self._handle_py_ver_compat_for_input_str(server, True), username=self._username, pkey=key,
                    password=self._password, allow_agent=False, look_for_keys=True,
                    timeout=FIRST_RECV_TIMEOUT)
        except AuthenticationException:
            return action_result.set_status(phantom.APP_ERROR, SSH_AUTHENTICATION_FAILED_ERR_MSG)
        except BadHostKeyException as e:
            err = self._get_error_message_from_exception(e)
            error_msg = "{}. {}".format(SSH_BAD_HOST_KEY_ERR_MSG, err)
            return action_result.set_status(phantom.APP_ERROR, error_msg)
        except SocketError:
            error_msg = "{}. {}".format(SSH_ERR_CONNECTION_FAILED, SSH_FAILED_TO_RESOLVE_ERR_MSG.format(server=server))
            return action_result.set_status(phantom.APP_ERROR, error_msg)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(SSH_ERR_CONNECTION_FAILED, err))

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

            self.debug_print("Calling 'exec_command' for command: {}".format(command))
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
            return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(SSH_ERR_SHELL_SEND_COMMAND.format(command), err)), None, None

        self.debug_print("Command executed successfully")
        return action_result.set_status(phantom.APP_SUCCESS, SSH_SUCC_CMD_EXEC), output, exit_status

    def _get_output(self, action_result, timeout, passwd, suppress):
        sendpw = True
        output = self._handle_py_ver_compat_for_input_str("", True)
        i = 1
        stime = int(time.time())
        if not suppress:
            self.save_progress("Executing command")
        try:
            while True:
                ctime = int(time.time())
                if (timeout and ctime - stime >= timeout):
                    err = 'Error: Timeout after {} seconds'.format(timeout)
                    try:
                        output = self._handle_py_ver_compat_for_input_str(output, True).decode("utf-8")
                    except Exception:
                        return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(err, SSH_DECODE_OUTPUT_ERR_MSG)), "", 1
                    return action_result.set_status(phantom.APP_ERROR, err), output, 1
                elif (self._shell_channel.recv_ready()):
                    output += self._shell_channel.recv(8192)
                    # This is pretty messy but it's just the way it is I guess
                    if (sendpw and passwd):
                        try:
                            self._shell_channel.send("{}\n".format(passwd))
                            if not self._pseudo_terminal:
                                output += self._handle_py_ver_compat_for_input_str("\n", True)
                        except socket.error:
                            pass
                        sendpw = False
                # Exit status AND nothing left in output
                elif (self._shell_channel.exit_status_ready() and not self._shell_channel.recv_ready()):
                    break
                else:
                    time.sleep(1)
                    if not suppress:
                        self.send_progress("Executing command" + "." * i)
                        i = i % 5 + 1
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err), "", None

        try:
            output = self._handle_py_ver_compat_for_input_str(output, True).decode("utf-8")
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, SSH_DECODE_OUTPUT_ERR_MSG), "", 1

        return action_result.set_status(phantom.APP_SUCCESS), output, self._shell_channel.recv_exit_status()

    def _clean_stdout(self, stdout, passwd):

        if stdout is None:
            return None

        try:
            lines = []
            for index, line in enumerate(stdout.splitlines()):
                if (passwd and passwd in line) or ("[sudo] password for" in line):
                    if passwd and passwd in line:
                        self.debug_print("Password found at index: {}".format(index))
                    continue
                lines.append(line)
        except:
            return None

        return '\n'.join(lines)

    def _output_for_exit_status(self, action_result, exit_status,
                                output_on_err, output_on_succ):
        # Shell returned an error
        if exit_status:
            action_result.set_status(phantom.APP_ERROR, output_on_err)
            d = {"output": output_on_err}
        else:
            action_result.set_status(phantom.APP_SUCCESS, SSH_SUCC_CMD_SUCCESS)
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
        except:
            return action_result.set_status(phantom.APP_ERROR, SSH_HOSTNAME_OR_IP_NOT_SPECIFIED_ERR_MSG)

        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            self.save_progress(SSH_ERR_CONNECTIVITY_TEST)
            return action_result.get_status()
        self.save_progress(SSH_CONNECTION_ESTABLISHED)
        self.save_progress("Executing 'uname' command...")

        # Get Linux Distribution
        cmd = "uname -a"
        status_code, stdout, exit_status = self._send_command(cmd, action_result, suppress=True, timeout=self._timeout)

        # Couldn't send command
        if phantom.is_fail(status_code):
            return status_code

        # Some version of mac
        if (exit_status == 0 and stdout.split()[0] == "Darwin"):
            self.OS_TYPE = OS_MAC
        self.debug_print("ssh uname {}".format(stdout))

        self.save_progress(SSH_SUCC_CONNECTIVITY_TEST)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _exec_command(self, param):

        self.debug_print("Starting 'execute program' action function")

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]

        self.debug_print("Calling 'start_connection'..")
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTION_ESTABLISHED)

        # As it turns out, even if the data type is "numeric" in the json
        # the data will end up being a string after you receive it

        # integer validation for 'timeout' action parameter
        timeout = param.get(SSH_JSON_TIMEOUT)
        if timeout is not None:
            ret_val, timeout = self._validate_integer(action_result, timeout, SSH_JSON_TIMEOUT, False)
            if phantom.is_fail(ret_val):
                timeout = self._timeout
                self.debug_print("Invalid value provided in the timeout parameter of the execute program action. {}".format(SSH_ASSET_TIMEOUT_MSG))
        else:
            timeout = self._timeout
            self.debug_print("No value found in the timeout parameter of the execute program action. {}".format(SSH_ASSET_TIMEOUT_MSG))

        script_file = param.get(SSH_JSON_SCRIPT_FILE)
        if script_file:
            try:
                with open(script_file, 'r') as f:
                    cmd = f.read()
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                err_msg = "{}. {}".format(SSH_UNABLE_TO_READ_SCRIPT_FILE_ERR_MSG.format(script_file=script_file), err)
                return action_result.set_status(phantom.APP_ERROR, err_msg)
        else:
            try:
                cmd = param[SSH_JSON_CMD]
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, SSH_COMMAND_OR_SCRIPT_FILE_NOT_PROVIDED_ERR_MSG)

        # Command needs to be run as root
        if (not self._root and cmd.split()[0] == "sudo"):
            passwd = self._password
            if passwd is None:
                return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)
        else:
            passwd = ""

        self.debug_print("Sending command for execution")
        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=timeout)

        # If command failed to send
        if phantom.is_fail(status_code):
            action_result.add_data({"output": stdout})
            return action_result.get_status()

        action_result = self._output_for_exit_status(action_result, exit_status,
                stdout, stdout)

        self.debug_print("'exec_command' action executed successfully")
        return action_result.get_status()

    def _reboot_server(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTION_ESTABLISHED)

        cmd = "sudo -S shutdown -r now"
        passwd = self._password
        root = self._root
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        # If command failed to send
        if phantom.is_fail(status_code):
            return action_result.get_status()

        # no exit status code is returned, in case the server is successfully rebooted
        if exit_status == -1:
            action_result.set_status(phantom.APP_SUCCESS, "Exit status: {}. {}".format(exit_status, SSH_VERIFY_LAST_REBOOT_TIME_MSG))
            d = {"output": stdout}
        # Shell returned an error
        elif exit_status:
            action_result.set_status(phantom.APP_ERROR, stdout)
            d = {"output": stdout}
        else:
            action_result.set_status(phantom.APP_SUCCESS, SSH_SUCC_CMD_SUCCESS)
            d = {"output": SSH_SHELL_NO_ERRORS}

        action_result.add_data(d)
        action_result.update_summary({"exit_status": exit_status})

        return action_result.get_status()

    def _shutdown_server(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTION_ESTABLISHED)

        cmd = "sudo -S shutdown -h now"
        passwd = self._password
        root = self._root
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        # If command failed to send
        if phantom.is_fail(status_code):
            return action_result.get_status()

        # verifying whether the endpoint has successfully shutdown or not
        time.sleep(15)
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            d = {"output": SSH_SHELL_NO_ERRORS}
            action_result.add_data(d)
            action_result.update_summary({"exit_status": exit_status})
            return action_result.set_status(phantom.APP_SUCCESS, "{}. {}".format(SSH_ENDPOINT_SHUTDOWN_MSG, SSH_SUCC_CMD_SUCCESS))

        action_result = self._output_for_exit_status(action_result, exit_status,
                stdout, SSH_SHELL_NO_ERRORS)

        return action_result.get_status()

    def _list_processes(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTION_ESTABLISHED)

        # excl_root = param.get(SSH_JSON_EXCL_ROOT, False)

        # ps on mac will always show the full username, ps on linux will
        #  only show usernames of <= 8 characters unless otherwise specified
        fuser = "" if self.OS_TYPE == OS_MAC else ":32"
        cmd = "ps c -Ao user{},uid,pid,ppid,stime,command".format(fuser)

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
                    if (i == len(headers) - 1):
                        d[headers[i].lower()] = ' '.join(r[i:])
                    else:
                        d[headers[i].lower()] = r[i]
                ll.append(d.copy())

            action_result.add_data({"processes": ll})
            action_result.update_summary({"total_processes": len(ll)})

            # result.set_status(phantom.APP_SUCCESS, SSH_SUCC_CMD_SUCCESS)
            action_result.set_status(phantom.APP_SUCCESS)
        except:
            action_result.set_status(phantom.APP_ERROR, SSH_UNABLE_TO_PARSE_OUTPUT_OF_CMD.format(cmd))

        return action_result

    def _kill_process(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTION_ESTABLISHED)

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
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)
        cmd = "sudo -S kill -SIGKILL {}".format(pid)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        action_result = self._output_for_exit_status(action_result, exit_status,
                stdout, SSH_PID_TERMINATED_MSG.format(pid=pid))

        return action_result.get_status()

    def _logout_user(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTION_ESTABLISHED)

        user_name = param[SSH_JSON_USER]
        passwd = self._password
        root = self._root
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)
        cmd = "sudo -S pkill -SIGKILL -u {}".format(user_name)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        action_result = self._output_for_exit_status(action_result, exit_status,
                stdout, SSH_LOGOFF_USER_MSG.format(username=user_name))

        return action_result.get_status()

    def _list_connections(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTION_ESTABLISHED)

        passwd = self._password
        root = self._root
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)
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
        if (self.OS_TYPE == OS_MAC):
            return self._list_connections_mac(param, action_result, passwd,
                    local_addr, local_port, remote_addr, remote_port)

        cmd = 'sudo -S netstat -etnp'

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        action_result.update_summary({"exit_status": exit_status})
        if exit_status:
            action_result.add_data({"output": stdout})
            if not stdout:
                return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(SSH_NO_SHELL_OUTPUT_ERR_MSG, SSH_IS_NETSTAT_INSTALLED_MSG))
            return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(SSH_SHELL_OUTPUT_ERR_MSG.format(stdout=stdout), SSH_IS_NETSTAT_INSTALLED_MSG))

        action_result = self._parse_connections(action_result, stdout, cmd,
                            local_addr, local_port, remote_addr, remote_port)

        return action_result.get_status()

    def _parse_connections(self, action_result, stdout, cmd, la, lp, ra, rp):
        """ Process output for connections
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
                    s = r[3].split(':')
                    d["local_port"] = s[-1]
                    if (lp and d["local_port"] != lp):
                        continue
                    del s[-1]
                    d["local_ip"] = ":".join(s)
                    if (la and d["local_ip"] != la):
                        continue
                except:           # Some error parsing
                    d["local_port"] = ""
                    d["local_ip"] = ""
                try:
                    s = r[4].split(':')
                    d["remote_port"] = s[-1]
                    if (rp and d["remote_port"] != rp):
                        continue
                    del s[-1]
                    d["remote_ip"] = ":".join(s)
                    if (ra and d["remote_ip"] != ra):
                        continue
                except:           # Some error parsing
                    d["remote_port"] = ""
                    d["remote_ip"] = ""
                d["state"] = r[5]
                d["uid"] = r[6]
                d["inode"] = r[7]
                try:
                    if (r[8] == "-"):
                        d["pid"] = ""
                        d["cmd"] = ""
                    else:
                        s = r[8].split('/')
                        d["pid"] = s[0]
                        del s[0]
                        d["cmd"] = "/".join(s)
                except:
                    d["pid"] = ""
                    d["cmd"] = ""
                ll.append(d.copy())

            action_result.add_data({"connections": ll})

            action_result.set_status(phantom.APP_SUCCESS, SSH_SUCC_CMD_SUCCESS)
        except:
            action_result.set_status(phantom.APP_ERROR, SSH_UNABLE_TO_PARSE_OUTPUT_OF_CMD.format(cmd))

        return action_result

    def _list_connections_mac(self, param, action_result, passwd,
            local_addr, local_port, remote_addr, remote_port):

        cmd = "sudo -S lsof -nP -i"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        action_result.update_summary({"exit_status": exit_status})
        if exit_status:
            action_result.add_data({"output": stdout})
            if not stdout:
                return action_result.set_status(phantom.APP_ERROR, SSH_NO_SHELL_OUTPUT_ERR_MSG)
            return action_result.set_status(phantom.APP_ERROR, SSH_SHELL_OUTPUT_ERR_MSG.format(stdout=stdout))

        action_result = self._parse_connections_mac(action_result, stdout, cmd,
                            local_addr, local_port, remote_addr, remote_port)

        return action_result.get_status()

    def _parse_connections_mac(self, action_result, stdout, cmd, la, lp, ra, rp):
        """ Process output for connections
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
                d['cmd'] = r[0]
                d['pid'] = r[1]
                d['uid'] = r[2]
                d['fd'] = r[3]
                d['type'] = r[4]
                d['device'] = r[5]
                d['sizeoff'] = r[6]
                d['protocol'] = r[7]
                n = r[8].split('->')
                if len(n) == 2:
                    # Get Local
                    s = n[0].split(':')
                    d['local_port'] = s[-1]
                    if lp and d['local_port'] != lp:
                        continue
                    del s[-1]
                    d['local_ip'] = ':'.join(s)
                    if la and d['local_ip'] != la:
                        continue
                    # Get Remote
                    s = n[1].split(':')
                    d['remote_port'] = s[-1]
                    if rp and d['remote_port'] != rp:
                        continue
                    del s[-1]
                    d['remote_ip'] = ':'.join(s)
                    if ra and d['remote_ip'] != ra:
                        continue
                else:
                    # If there is no remote connection (as many things will display),
                    #  and they are being filtered, don't add
                    if (rp or ra):
                        continue
                    s = n[0].split(':')
                    d['local_port'] = s[-1]
                    if (lp and d['local_port'] != lp):
                        continue
                    del s[-1]
                    d['local_ip'] = ':'.join(s)
                    if (la and d['local_ip'] != la):
                        continue
                    d['remote_port'] = ""
                    d['remote_ip'] = ""
                try:
                    d['state'] = r[9][1:-1]  # Ignore paranthesis
                except:
                    d['state'] = ""
                ll.append(d.copy())

            action_result.add_data({"connections": ll})

            action_result.set_status(phantom.APP_SUCCESS, SSH_SUCC_CMD_SUCCESS)
        except:
            action_result.set_status(phantom.APP_ERROR, SSH_UNABLE_TO_PARSE_OUTPUT_OF_CMD.format(cmd))

        return action_result

    def _list_fw_rules(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTION_ESTABLISHED)

        if (self.OS_TYPE == OS_MAC):
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_FIREWALL_CMDS_NOT_SUPPORTED)

        passwd = self._password
        root = self._root
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)
        prot = param.get(SSH_JSON_PROTOCOL, "")
        port = param.get(SSH_JSON_PORT, "")

        # integer validation of 'port' action parameter
        if port:
            ret_val, port = self._validate_integer(action_result, port, SSH_JSON_PORT)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
        port = str(port)
        chain = param.get(SSH_JSON_CHAIN, "")

        cmd = 'sudo -S iptables -L {} --line-numbers -n'.format(chain)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        action_result.update_summary({"exit_status": exit_status})
        if exit_status:
            action_result.add_data({"output": stdout})
            if not stdout:
                return action_result.set_status(phantom.APP_ERROR, SSH_NO_SHELL_OUTPUT_ERR_MSG)
            return action_result.set_status(phantom.APP_ERROR, SSH_SHELL_OUTPUT_ERR_MSG.format(stdout=stdout))

        action_result = self._filter_fw_rules(action_result, stdout, cmd, prot, port)

        return action_result.get_status()

    def _filter_fw_rules(self, action_result, stdout, cmd, prot, port):

        try:
            ll = []
            cur_chain = ""
            d = {}
            rows = stdout.splitlines()

            i = 0
            while (i < len(rows)):
                cur_chain = rows[i].split()[1]  # Name of chain
                i += 2                          # Skip header row
                while (i < len(rows)):
                    if (rows[i] == ""):
                        i += 1
                        break                   # New Chain
                    row = rows[i].split()
                    if (len(row) >= 6):         # This is hopefully always true
                        d["chain"] = cur_chain
                        d["num"] = row[0]
                        d["target"] = row[1]
                        if (prot and row[2] != prot):
                            i += 1
                            continue
                        d["protocol"] = row[2]
                        d["source"] = row[4]
                        d["destination"] = row[5]
                        try:                    # the rest can contain port numbers, comments, and other things
                            the_rest = " ".join(row[6:])
                        except:
                            the_rest = ""
                        if (port and port not in the_rest):
                            i += 1
                            continue
                        d["options"] = the_rest
                        ll.append(d.copy())
                    i += 1

            action_result.add_data({"rules": ll})
            action_result.set_status(phantom.APP_SUCCESS, SSH_SUCC_CMD_SUCCESS)
        except:
            action_result.set_status(phantom.APP_ERROR, SSH_UNABLE_TO_PARSE_OUTPUT_OF_CMD.format(cmd))

        return action_result

    def _block_ip(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTION_ESTABLISHED)

        if (self.OS_TYPE == OS_MAC):
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_FIREWALL_CMDS_NOT_SUPPORTED)

        no_ip = True
        no_port = True
        passwd = self._password
        root = self._root
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)

        protocol = param[SSH_JSON_PROTOCOL]
        direction = "INPUT" if param[SSH_JSON_DIRECTION].lower() == "in" else "OUTPUT"

        try:
            if direction == "INPUT":
                remote_ip = "-s {}".format(param[SSH_JSON_REMOTE_IP])
            else:
                remote_ip = "-d {}".format(param[SSH_JSON_REMOTE_IP])
            no_ip = False
        except:
            remote_ip = ""

        try:
            remote_port = param[SSH_JSON_REMOTE_PORT]

            # integer validation of 'remote_port' action parameter
            ret_val, remote_port = self._validate_integer(action_result, remote_port, SSH_JSON_REMOTE_PORT, True)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if direction == "INPUT":
                port = "--destination-port {}".format(remote_port)
            else:
                port = "-dport {}".format(remote_port)
            no_port = False
        except:
            port = ""

        try:
            comment = "-m comment --comment '{} -- Added by Phantom'".format(param[SSH_JSON_COMMENT])
        except:
            comment = "-m comment --comment 'Added by Phantom'"

        if (no_ip and no_port):
            return action_result.set_status(phantom.APP_ERROR, SSH_REMOTE_IP_OR_PORT_NOT_SPECIFIED_ERR_MSG)

        cmd = "sudo -S iptables -I {} -p {} {} {} -j DROP {}".format(direction,
                                                                      protocol, remote_ip,
                                                                      port, comment)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        if exit_status:
            action_result.add_data({"output": stdout})
            if not stdout:
                return action_result.set_status(phantom.APP_ERROR, SSH_NO_SHELL_OUTPUT_ERR_MSG)
            return action_result.set_status(phantom.APP_ERROR, SSH_SHELL_OUTPUT_ERR_MSG.format(stdout=stdout))

        action_result = self._save_iptables(action_result, passwd)

        return action_result.get_status()

    def _delete_fw_rule(self, param):
        """ Should this be changed to only delete rules
             created by Phantom?
        """
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTION_ESTABLISHED)

        if (self.OS_TYPE == OS_MAC):
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_FIREWALL_CMDS_NOT_SUPPORTED)

        passwd = self._password
        root = self._root
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)
        chain = param[SSH_JSON_CHAIN]
        number = param[SSH_JSON_NUMBER]

        # integer validation for 'number' action parameter
        ret_val, number = self._validate_integer(action_result, number, SSH_JSON_NUMBER, True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        cmd = "sudo -S iptables -D {} {}".format(chain, number)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        if exit_status:
            action_result.add_data({"output": stdout})
            if not stdout:
                return action_result.set_status(phantom.APP_ERROR, SSH_NO_SHELL_OUTPUT_ERR_MSG)
            return action_result.set_status(phantom.APP_ERROR, SSH_SHELL_OUTPUT_ERR_MSG.format(stdout=stdout))

        action_result = self._save_iptables(action_result, passwd)

        return action_result.get_status()

    def _save_iptables(self, action_result, passwd):
        """ iptables needs to be saved after a command modifies it
        """
        cmd = "sudo -S service iptables save"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result

        action_result = self._output_for_exit_status(action_result, exit_status,
                "{} Is the iptables service running?".format(stdout), SSH_SHELL_NO_ERRORS)

        return action_result

    def _get_file(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTION_ESTABLISHED)

        file_path = param[SSH_JSON_FILE_PATH]
        # /some/dir/file_name
        file_name = file_path.split('/')[-1]
        if hasattr(Vault, 'get_vault_tmp_dir'):
            vault_path = '{}/{}'.format(Vault.get_vault_tmp_dir(), file_name)
        else:
            vault_path = '/vault/tmp/{}'.format(file_name)

        sftp = self._ssh_client.open_sftp()
        try:
            sftp.get(file_path, vault_path)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            sftp.close()
            return action_result.set_status(phantom.APP_ERROR, SSH_GET_FILE_ERR_MSG.format(err=err))

        sftp.close()
        vault_ret = Vault.add_attachment(vault_path, self.get_container_id(), file_name=file_name)
        if vault_ret.get('succeeded'):
            action_result.set_status(phantom.APP_SUCCESS, "Transferred file")
            summary = {
                    phantom.APP_JSON_VAULT_ID: vault_ret[phantom.APP_JSON_HASH],
                    phantom.APP_JSON_NAME: file_name,
                    phantom.APP_JSON_SIZE: vault_ret.get(phantom.APP_JSON_SIZE)}
            action_result.update_summary(summary)

        return action_result.get_status()

    def _put_file(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTION_ESTABLISHED)

        # fetching phantom vault details
        try:
            success, message, vault_meta_info = ph_rules.vault_info(vault_id=param[SSH_JSON_VAULT_ID])
            vault_meta_info = list(vault_meta_info)
            if not success or not vault_meta_info:
                error_msg = " Error Details: {}".format(unquote(message)) if message else ''
                return action_result.set_status(phantom.APP_ERROR, "{}.{}".format(SSH_UNABLE_TO_RETREIVE_VAULT_ITEM_ERR_MSG, error_msg))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(SSH_UNABLE_TO_RETREIVE_VAULT_ITEM_ERR_MSG, err))

        # phantom vault file path
        file_path = vault_meta_info[0].get('path')

        # phantom vault file name
        dest_file_name = vault_meta_info[0].get('name')
        file_dest = param[SSH_JSON_FILE_DEST]

        # Returning an error if the filename is included in the file_destination path
        if dest_file_name in file_dest:
            return action_result.set_status(phantom.APP_ERROR, SSH_EXCLUDE_FILENAME_ERR_MSG)

        destination_path = "{}{}{}".format(param[SSH_JSON_FILE_DEST], '/' if param[SSH_JSON_FILE_DEST][-1] != '/' else '', dest_file_name)

        sftp = self._ssh_client.open_sftp()
        try:
            sftp.put(file_path, destination_path)
        except FileNotFoundError as e:
            err = self._get_error_message_from_exception(e)
            sftp.close()
            err = "{}. {}".format(err, SSH_FILE_NOT_FOUND_ERR_MSG)
            return action_result.set_status(phantom.APP_ERROR, SSH_PUT_FILE_ERR_MSG.format(err=err))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            sftp.close()
            return action_result.set_status(phantom.APP_ERROR, SSH_PUT_FILE_ERR_MSG.format(err=err))
        sftp.close()

        summary = {'file_sent': destination_path }
        action_result.update_summary(summary)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _parse_generic(self, data=None, headers=None, newline='\n', best_fit=True, new_header_names=None, action_result=None):
        # header_locator should be a list of the headers returned in the results
        # ie for df -hP, this would be ['Filesystem', 'Size', 'Used', 'Avail', 'Use%', 'Mounted on']
        # if best_fit is True, all rows are expected to have the same number of columns as headers.
        # if best_fit is False, best attempts to fill data will be made
        # new header names will be used in the output in place of the headers= fields.
        results = []
        for line in data.split(newline):
            found_header = False
            for header in headers:
                if header in line and header != '':
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
                temp['error_message'] = SSH_PARSE_HEADER_ERR.format(len(headers), headers, len(line), line)
                continue

            if best_fit:
                for num, val in enumerate(line.strip().split()):
                    if headers[num] == '':
                        continue
                    else:
                        if new_header_names:
                            temp[new_header_names[num]] = val
                        else:
                            temp[headers[num]] = val
            else:
                for num in range(0, len(headers)):
                    linedata = line.strip().split()
                    if new_header_names:
                        if new_header_names[num] == '' and headers[num] == '':
                            continue
                    elif headers[num] == '':
                        continue
                    if new_header_names:
                        try:
                            temp[new_header_names[num]] = linedata[num]
                        except:
                            temp[new_header_names[num]] = ''
                    else:
                        try:
                            temp[headers[num]] = linedata[num]
                        except:
                            temp[headers[num]] = ''
            temp['raw'] = line
            results.append(temp)
        return results

    def _get_disk_usage(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTION_ESTABLISHED)

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
                return action_result.set_status(phantom.APP_ERROR, SSH_NO_SHELL_OUTPUT_ERR_MSG)
            return action_result.set_status(phantom.APP_ERROR, SSH_SHELL_OUTPUT_ERR_MSG.format(stdout=stdout))

        stdout2 = stdout.replace("%", "")  # clean up % from text
        result = self._parse_generic(data=stdout2,
                   headers=['Filesystem', 'Size', 'Used', 'Avail', 'Use%', 'Mounted on'],
                   newline='\n')
        action_result.add_data(result)
        action_result.update_summary({"exit_status": exit_status})

        return action_result.get_status()

    def _get_memory_usage(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code = self._start_connection(action_result, endpoint)
        if phantom.is_fail(status_code):
            return action_result.get_status()
        self.debug_print(SSH_CONNECTION_ESTABLISHED)

        passwd = self._password
        root = self._root
        if root:
            passwd = None

        cmd = "free -h"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd, timeout=self._timeout)

        if phantom.is_fail(status_code):
            return action_result.get_status()

        if exit_status:
            action_result.add_data({"output": stdout})
            if not stdout:
                return action_result.set_status(phantom.APP_ERROR, SSH_NO_SHELL_OUTPUT_ERR_MSG)
            return action_result.set_status(phantom.APP_ERROR, SSH_SHELL_OUTPUT_ERR_MSG.format(stdout=stdout))

        result = self._parse_generic(data=stdout,
                       headers=['', 'total', 'used', 'free', 'shared', 'buff/cache', "available"],
                       newline='\n', best_fit=False,
                       new_header_names=['Type', 'Total', 'Used', 'Free', 'Shared', 'Buff/Cache', 'Available'])
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

        if (action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)
        elif (action_id == ACTION_ID_EXEC_COMMAND):
            ret_val = self._exec_command(param)
        elif (action_id == ACTION_ID_REBOOT_SERVER):
            ret_val = self._reboot_server(param)
        elif (action_id == ACTION_ID_SHUTDOWN_SERVER):
            ret_val = self._shutdown_server(param)
        elif (action_id == ACTION_ID_LIST_PROCESSES):
            ret_val = self._list_processes(param)
        elif (action_id == ACTION_ID_TERMINATE_PROCESS):
            ret_val = self._kill_process(param)
        elif (action_id == ACTION_ID_LOGOUT_USER):
            ret_val = self._logout_user(param)
        elif (action_id == ACTION_ID_LIST_CONN):
            ret_val = self._list_connections(param)
        elif (action_id == ACTION_ID_LIST_FW_RULES):
            ret_val = self._list_fw_rules(param)
        elif (action_id == ACTION_ID_BLOCK_IP):
            ret_val = self._block_ip(param)
        elif (action_id == ACTION_ID_DELETE_FW_RULE):
            ret_val = self._delete_fw_rule(param)
        elif (action_id == ACTION_ID_GET_FILE):
            ret_val = self._get_file(param)
        elif (action_id == ACTION_ID_GET_MEMORY_USAGE):
            ret_val = self._get_memory_usage(param)
        elif (action_id == ACTION_ID_GET_DISK_USAGE):
            ret_val = self._get_disk_usage(param)
        elif (action_id == ACTION_ID_PUT_FILE):
            ret_val = self._put_file(param)

        return ret_val


if __name__ == '__main__':

    # import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SshConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
