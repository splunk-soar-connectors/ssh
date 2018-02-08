# --
# File: phssh_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --
# ---------------
# Phantom ssh app
# ---------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault as Vault

# Import local
from phssh_consts import *

# import paramiko
import os
os.sys.path.insert(0, "{}/paramikossh".format(os.path.dirname(os.path.abspath(__file__))))  # noqa
import paramiko
import socket
import sys
import simplejson as json
import time

# Timeouts in seconds
FIRST_RECV_TIMEOUT = 30
SECOND_ONWARDS_RECV_TIMEOUT = 1
SEND_TIMEOUT = 2


class SshConnector(BaseConnector):

    ACTION_ID_EXEC_COMMAND = "ssh_execute_command"
    ACTION_ID_REBOOT_SERVER = "ssh_reboot_server"
    ACTION_ID_SHUTDOWN_SERVER = "ssh_shutdown_server"
    ACTION_ID_LIST_PROCESSES = "ssh_list_processes"
    ACTION_ID_TERMINATE_PROCESS = "ssh_kill_process"
    ACTION_ID_LOGOUT_USER = "ssh_logout_user"
    ACTION_ID_LIST_FW_RULES = "ssh_list_fw_rules"
    ACTION_ID_BLOCK_IP = "ssh_block_ip"
    ACTION_ID_DELETE_FW_RULE = "ssh_delete_fw_rule"
    ACTION_ID_LIST_CONN = "ssh_list_conn"
    ACTION_ID_GET_FILE = "ssh_get_file"
    ACTION_ID_GET_MEMORY_USAGE = "get_memory_usage"
    ACTION_ID_GET_DISK_USAGE = "get_disk_usage"
    ACTION_ID_PUT_FILE = "ssh_put_file"

    OS_LINUX = 0
    OS_MAC = 1

    def __init__(self):
        super(SshConnector, self).__init__()

        self._ssh_client = None
        self._shell_channel = None
        self.OS_TYPE = self.OS_LINUX

    def _start_connection(self, server):

        self.debug_print("PARAMIKO VERSION", paramiko.__version__)

        config = self.get_config()
        user = config[SSH_JSON_USERNAME]
        password = config.get(SSH_JSON_PASSWORD, None)
        rsa_key_file = config.get(SSH_JSON_RSA_KEY, None)
        if rsa_key_file is None and password is None:
            return self.set_status(phantom.APP_ERROR, "Need to specify either password or RSA key"), None
        if rsa_key_file:
            try:
                key = paramiko.RSAKey.from_private_key_file("/home/phantom-worker/.ssh/{}".format(rsa_key_file))
                password = None
            except Exception as e:
                return self.set_status(phantom.APP_ERROR, SSH_ERR_CONNECTION_FAILED, e), None
        else:
            key = None

        self._ssh_client = paramiko.SSHClient()
        self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, server)
        try:
            self._ssh_client.connect(hostname=server, username=user, pkey=key,
                    password=password, allow_agent=False, look_for_keys=True,
                    timeout=30)
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, SSH_ERR_CONNECTION_FAILED, e), None

        # Get Linux Distribution
        action_result = ActionResult({"a": ""})
        cmd = "uname -a"
        status_code, stdout, exit_status = self._send_command(cmd, action_result, suppress=True)

        # Couldn't send command
        if (phantom.is_fail(status_code)):
            return status_code, None

        # Some version of mac
        if (exit_status == 0 and stdout.split()[0] == "Darwin"):
            self.OS_TYPE = self.OS_MAC

        return phantom.APP_SUCCESS, stdout

    def _send_command(self, command, result, passwd="", timeout=0, suppress=False):
        """
           Args:
               command: command to send
               result:  object used to store the status
               passwd:  password, if command needs to be run with root
               timeout: how long to wait before terminating program 
               suppress: don't send message / heartbeat back to phantom
        """
        try:
            output = ""
            trans = self._ssh_client.get_transport()
            self._shell_channel = trans.open_session()
            self._shell_channel.get_pty()
            self._shell_channel.set_combine_stderr(True)
            self._shell_channel.exec_command(command)
            result, data, exit_status = self._get_output(result, timeout, passwd, suppress)
            if (phantom.is_fail(result.get_status())):
                return (result.set_status(phantom.APP_ERROR, result.get_message()), None, None)
            output += data
            output = self._clean_stdout(output, passwd)
        except Exception as e:
            return (result.set_status(phantom.APP_ERROR, SSH_ERR_SHELL_SEND_COMMAND, e, command),
                    None, None)

        return (result.set_status(phantom.APP_SUCCESS, SSH_SUCC_CMD_EXEC),
                output, exit_status)

    def _get_output(self, result, timeout, passwd, suppress):
        sendpw = True
        self._shell_channel.settimeout(2)
        output = ""
        i = 1
        stime = int(time.time())
        if not suppress:
            self.save_progress("Executing command")
        try:
            while True:
                ctime = int(time.time())
                if (self._shell_channel.recv_ready()):
                    output += self._shell_channel.recv(8192)
                    # This is pretty messy but it's just the way it is I guess
                    if (sendpw and passwd):
                        try:
                            self._shell_channel.send("{}\n".format(passwd))
                        except socket.error:
                            pass
                        sendpw = False
                # Exit status AND nothing left in output
                elif (self._shell_channel.exit_status_ready() and not self._shell_channel.recv_ready()):
                    break
                elif (timeout and ctime - stime >= timeout):
                    result.set_status(phantom.APP_ERROR, "Error: Timeout")
                    return (result, None, None)
                else:
                    time.sleep(1)
                    if not suppress:
                        self.send_progress("Executing command" + "." * i)
                        i = i % 5 + 1
        except Exception as e:
            result.set_status(phantom.APP_ERROR, str(e))
            return (result, None, None)
        result.set_status(phantom.APP_SUCCESS)
        return (result, output, self._shell_channel.recv_exit_status())

    def _clean_stdout(self, stdout, passwd):
        if (stdout is None):
            return None

        try:
            lines = stdout.splitlines()
            while (True):
                if (passwd and passwd in lines[0]):
                    lines.pop(0)
                    continue
                if ("[sudo] password for" in lines[0]):
                    lines.pop(0)
                    continue
                if (lines[0] == ""):
                    lines.pop(0)
                    continue
                break
        except:
            return None

        return ('\n'.join(lines))

    def _output_for_exit_status(self, result, exit_status,
                                output_on_err, output_on_succ):
        # Shell returned an error
        if (exit_status):
            result.set_status(phantom.APP_ERROR, output_on_err)
            d = {"output": output_on_err}
        else:
            result.set_status(phantom.APP_SUCCESS, SSH_SUCC_CMD_SUCCESS)
            d = {"output": output_on_succ}

        result.add_data(d)
        result.update_summary({"exit_status": exit_status})
        # result.add_data({"exit_status": exit_status})

        return result

    def _test_connectivity(self, param):

        self.save_progress("Testing ssh connection")

        try:
            endpoint = self.get_config()['test_device']
        except:
            return self.set_status(phantom.APP_ERROR, "Need to specify a hostname or IP to connect to.")

        status_code, uname_str = self._start_connection(endpoint)
        if (phantom.is_fail(status_code)):
            self.save_progress(SSH_ERR_CONNECTIVITY_TEST)
            return self.append_to_message(SSH_ERR_CONNECTIVITY_TEST)
        self.debug_print("ssh uname", uname_str)

        return self.set_status_save_progress(phantom.APP_SUCCESS, SSH_SUCC_CONNECTIVITY_TEST)

    def _exec_command(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code, uname_str = self._start_connection(endpoint)
        if (phantom.is_fail(status_code)):
            action_result.set_status(self.get_status(), self.get_status_message())
            return action_result.get_status()
        self.debug_print("ssh uname", uname_str)

        # As it turns out, even if the data type is "numeric" in the json
        #  the data will end up being a string after you recieve it
        timeout = int(param.get(SSH_JSON_TIMEOUT, 60))
        config = self.get_config()
        cmd = param[SSH_JSON_CMD]
        root = config.get(SSH_JSON_ROOT, False)
        # Command needs to be run as root
        if (not root and cmd.split()[0] == "sudo"):
            passwd = config.get(SSH_JSON_PASSWORD, None)
            if passwd is None:
                return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)
        else:
            passwd = ""

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd,
                                                              timeout=timeout)

        # If command failed to send
        if (phantom.is_fail(status_code)):
            return action_result.get_status()

        action_result = self._output_for_exit_status(action_result, exit_status,
                stdout, stdout)

        return action_result.get_status()

    def _reboot_server(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code, uname_str = self._start_connection(endpoint)
        if (phantom.is_fail(status_code)):
            action_result.set_status(self.get_status(), self.get_status_message())
            return action_result.get_status()
        self.debug_print("ssh uname", uname_str)

        cmd = "sudo -S shutdown -r now"
        config = self.get_config()
        passwd = config.get(SSH_JSON_PASSWORD, None)
        root = config.get(SSH_JSON_ROOT, False)
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd)

        # If command failed to send
        if (phantom.is_fail(status_code)):
            return action_result.get_status()

        action_result = self._output_for_exit_status(action_result, exit_status,
                stdout, SSH_SHELL_NO_ERRORS)

        return action_result.get_status()

    def _shutdown_server(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code, uname_str = self._start_connection(endpoint)
        if (phantom.is_fail(status_code)):
            action_result.set_status(self.get_status(), self.get_status_message())
            return action_result.get_status()
        self.debug_print("ssh uname", uname_str)

        cmd = "sudo -S shutdown -h now"
        config = self.get_config()
        passwd = config.get(SSH_JSON_PASSWORD, None)
        root = config.get(SSH_JSON_ROOT, False)
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd)

        # If command failed to send
        if (phantom.is_fail(status_code)):
            return action_result.get_status()

        action_result = self._output_for_exit_status(action_result, exit_status,
                stdout, SSH_SHELL_NO_ERRORS)

        return action_result.get_status()

    def _list_processes(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code, uname_str = self._start_connection(endpoint)
        if (phantom.is_fail(status_code)):
            action_result.set_status(self.get_status(), self.get_status_message())
            return action_result.get_status()
        self.debug_print("ssh uname", uname_str)

        # excl_root = param.get(SSH_JSON_EXCL_ROOT, False)

        # ps on mac will always show the full username, ps on linx will
        #  only show usernames of <= 8 characters unless otherwise specified
        fuser = "" if self.OS_TYPE == self.OS_MAC else ":32"
        cmd = "ps c -Ao user{},uid,pid,ppid,stime,command".format(fuser)

        status_code, stdout, exit_status = self._send_command(cmd, action_result)

        if (phantom.is_fail(status_code)):
            return action_result.get_status()

        action_result = self._parse_processes(action_result, stdout, cmd)
        # action_result.update_summary({"exit_status": exit_status})

        return action_result.get_status()

    def _parse_processes(self, result, stdout, cmd):
        """
        STDOUT:
        USER  UID  PID  PPID  STIME  CMD
        """
        try:
            l = []  # List to store dictionaries
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
                l.append(d.copy())

            result.add_data({"processes": l})
            result.update_summary({"total_processes": len(l)})

            # result.set_status(phantom.APP_SUCCESS, SSH_SUCC_CMD_SUCCESS)
            result.set_status(phantom.APP_SUCCESS)
        except:
            result.set_status(phantom.APP_ERROR, SSH_UNABLE_TO_PARSE_OUTPUT_OF_CMD, cmd)

        return result

    def _kill_process(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code, uname_str = self._start_connection(endpoint)
        if (phantom.is_fail(status_code)):
            action_result.set_status(self.get_status(), self.get_status_message())
            return action_result.get_status()
        self.debug_print("ssh uname", uname_str)

        pid = param[SSH_JSON_PID]
        config = self.get_config()
        passwd = config.get(SSH_JSON_PASSWORD, None)
        root = config.get(SSH_JSON_ROOT, False)
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)
        cmd = "sudo -S kill -SIGKILL {}".format(pid)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd)

        if (phantom.is_fail(status_code)):
            return action_result.get_status()

        action_result = self._output_for_exit_status(action_result, exit_status,
                stdout, "Succesfully terminated pid {}".format(pid))

        return action_result.get_status()

    def _logout_user(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code, uname_str = self._start_connection(endpoint)
        if (phantom.is_fail(status_code)):
            action_result.set_status(self.get_status(), self.get_status_message())
            return action_result.get_status()
        self.debug_print("ssh uname", uname_str)

        user_name = param[SSH_JSON_USER]
        config = self.get_config()
        passwd = config.get(SSH_JSON_PASSWORD, None)
        root = config.get(SSH_JSON_ROOT, False)
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)
        cmd = "sudo -S pkill -SIGKILL -u {}".format(user_name)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd)

        if (phantom.is_fail(status_code)):
            return action_result.get_status()

        action_result = self._output_for_exit_status(action_result, exit_status,
                stdout, "Succesfully logged off  user \"{}\"".format(user_name))

        return action_result.get_status()

    def _list_connections(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code, uname_str = self._start_connection(endpoint)
        if (phantom.is_fail(status_code)):
            action_result.set_status(self.get_status(), self.get_status_message())
            return action_result.get_status()
        self.debug_print("ssh uname", uname_str)

        config = self.get_config()
        passwd = config.get(SSH_JSON_PASSWORD, None)
        root = config.get(SSH_JSON_ROOT, False)
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)
        local_addr = param.get(SSH_JSON_LOCAL_ADDR, "")
        local_port = param.get(SSH_JSON_LOCAL_PORT, "")
        remote_addr = param.get(SSH_JSON_REMOTE_ADDR, "")
        remote_port = param.get(SSH_JSON_REMOTE_PORT, "")

        # Macs have BSD netstat which doesn't give enough information
        if (self.OS_TYPE == self.OS_MAC):
            return self._list_connections_mac(param, action_result, passwd,
                    local_addr, local_port, remote_addr, remote_port)

        cmd = 'sudo -S netstat -etnp'

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd)

        if (phantom.is_fail(status_code)):
            return action_result.get_status()

        action_result.update_summary({"exit_status": exit_status})
        if (exit_status):
            action_result.set_status(phantom.APP_ERROR, "Shell returned \"{}\". Is netstat installed?".format(stdout))
            action_result.add_data({"output": stdout})
            return action_result.get_status()

        action_result = self._parse_connections(action_result, stdout, cmd,
                            local_addr, local_port, remote_addr, remote_port)

        return action_result.get_status()

    def _parse_connections(self, result, stdout, cmd, la, lp, ra, rp):
        """ Process output for connections
            PROTO Rec-Q Send-Q Local_Address Foreign_Address State User Inode Pid/Program_Name
        """
        try:
            l = []  # List to store dictionaries
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
                l.append(d.copy())

            result.add_data({"connections": l})

            result.set_status(phantom.APP_SUCCESS, SSH_SUCC_CMD_SUCCESS)
        except:
            result.set_status(phantom.APP_ERROR, SSH_UNABLE_TO_PARSE_OUTPUT_OF_CMD, cmd)

        return result

    def _list_connections_mac(self, param, action_result, passwd,
            local_addr, local_port, remote_addr, remote_port):

        cmd = "sudo -S lsof -nP -i"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd)

        if (phantom.is_fail(status_code)):
            return action_result.get_status()

        action_result.update_summary({"exit_status": exit_status})
        if (exit_status):
            action_result.set_status(phantom.APP_ERROR, "Shell returned \"{}\"".format(stdout))
            action_result.add_data({"output": stdout})
            return action_result.get_status()

        action_result = self._parse_connections_mac(action_result, stdout, cmd,
                            local_addr, local_port, remote_addr, remote_port)

        return action_result.get_status()

    def _parse_connections_mac(self, result, stdout, cmd, la, lp, ra, rp):
        """ Process output for connections
            COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME (STATE)?
        """
        try:
            l = []  # List to store dictionaries
            rows = stdout.splitlines()

            if (len(rows) <= 1):
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
                if (len(n) == 2):
                    # Get Local
                    s = n[0].split(':')
                    d['local_port'] = s[-1]
                    if (lp and d['local_port'] != lp):
                        continue
                    del s[-1]
                    d['local_ip'] = ':'.join(s)
                    if (la and d['local_ip'] != la):
                        continue
                    # Get Remote
                    s = n[1].split(':')
                    d['remote_port'] = s[-1]
                    if (rp and d['remote_port'] != rp):
                        continue
                    del s[-1]
                    d['remote_ip'] = ':'.join(s)
                    if (ra and d['remote_ip'] != ra):
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
                l.append(d.copy())

            result.add_data({"connections": l})

            result.set_status(phantom.APP_SUCCESS, SSH_SUCC_CMD_SUCCESS)
        except:
            result.set_status(phantom.APP_ERROR, SSH_UNABLE_TO_PARSE_OUTPUT_OF_CMD, cmd)

        return result

    def _list_fw_rules(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code, uname_str = self._start_connection(endpoint)
        if (phantom.is_fail(status_code)):
            action_result.set_status(self.get_status(), self.get_status_message())
            return action_result.get_status()
        self.debug_print("ssh uname", uname_str)

        if (self.OS_TYPE == self.OS_MAC):
            action_result.set_status(phantom.APP_ERROR, SSH_ERR_FIREWALL_CMDS_NOT_SUPPORTED)
            return action_result.get_status()

        config = self.get_config()
        passwd = config.get(SSH_JSON_PASSWORD, None)
        root = config.get(SSH_JSON_ROOT, False)
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)
        prot = param.get(SSH_JSON_PROTOCOL, "")
        port = param.get(SSH_JSON_PORT, "")
        chain = param.get(SSH_JSON_CHAIN, "")

        cmd = 'sudo -S iptables -L {} --line-numbers -n'.format(chain)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd)

        if (phantom.is_fail(status_code)):
            return action_result.get_status()

        action_result.update_summary({"exit_status": exit_status})
        if (exit_status):
            action_result.set_status(phantom.APP_ERROR, "Shell returned an error: \"{}\"".format(stdout))
            action_result.add_data({"output": stdout})
            return action_result.get_status()

        action_result = self._filter_fw_rules(action_result, stdout, cmd, prot, port)

        return action_result.get_status()

    def _filter_fw_rules(self, result, stdout, cmd, prot, port):

        try:
            l = []
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
                            continue
                        d["protocol"] = row[2]
                        d["source"] = row[4]
                        d["destination"] = row[5]
                        try:                    # the rest can contain port numbers, comments, and other things
                            the_rest = " ".join(row[6:])
                        except:
                            the_rest = ""
                        if (port and port not in the_rest):
                            continue
                        d["options"] = the_rest
                        l.append(d.copy())
                    i += 1

            result.add_data({"rules": l})
            result.set_status(phantom.APP_SUCCESS, SSH_SUCC_CMD_SUCCESS)
        except:
            result.set_status(phantom.APP_ERROR, SSH_UNABLE_TO_PARSE_OUTPUT_OF_CMD, cmd)

        return result

    def _block_ip(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code, uname_str = self._start_connection(endpoint)
        if (phantom.is_fail(status_code)):
            action_result.set_status(self.get_status(), self.get_status_message())
            return action_result.get_status()
        self.debug_print("ssh uname", uname_str)

        if (self.OS_TYPE == self.OS_MAC):
            action_result.set_status(phantom.APP_ERROR, SSH_ERR_FIREWALL_CMDS_NOT_SUPPORTED)
            return action_result.get_status()

        no_ip = True
        no_port = True
        config = self.get_config()
        passwd = config.get(SSH_JSON_PASSWORD, None)
        root = config.get(SSH_JSON_ROOT, False)
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)
        protocol = param[SSH_JSON_PROTOCOL]
        if (param[SSH_JSON_DIRECTION] == "In"):
            direction = "INPUT"
        else:
            direction = "OUTPUT"
        try:
            if (direction == "INPUT"):
                remote_ip = "-s {}".format(param[SSH_JSON_REMOTE_IP])
            else:
                remote_ip = "-d {}".format(param[SSH_JSON_REMOTE_IP])
            no_ip = False
        except:
            remote_ip = ""
        try:
            if (direction == "INPUT"):
                port = "--destination-port {}".format(param[SSH_JSON_PORT])
            else:
                port = "-dport {}".format(param[SSH_JSON_PORT])
            no_port = False
        except:
            port = ""
        try:
            comment = "-m comment --comment \"{} -- Added by Phantom\"".format(param[SSH_JSON_COMMENT])
        except:
            comment = "-m comment --comment \"Added by Phantom\""

        if (no_ip and no_port):
            action_result.set_status(phantom.APP_ERROR, "Need to specify remote ip or port to block")
            return action_result.get_status()

        cmd = "sudo -S iptables -I {} -p {} {} {} -j DROP {}".format(direction,
                                                                      protocol, remote_ip,
                                                                      port, comment)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd)

        if (phantom.is_fail(status_code)):
            return action_result.get_status()

        if (exit_status):
            action_result.set_status(phantom.APP_ERROR, "Shell returned an error: \"{}\"".format(stdout))
            action_result.add_data({"output": stdout})
            return action_result.get_status()

        action_result = self._save_iptables(action_result, passwd)

        return action_result.get_status()

    def _delete_fw_rule(self, param):
        """ Should this be changed to only delete rules
             created by Phantom?
        """
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code, uname_str = self._start_connection(endpoint)
        if (phantom.is_fail(status_code)):
            action_result.set_status(self.get_status(), self.get_status_message())
            return action_result.get_status()
        self.debug_print("ssh uname", uname_str)

        if (self.OS_TYPE == self.OS_MAC):
            action_result.set_status(phantom.APP_ERROR, SSH_ERR_FIREWALL_CMDS_NOT_SUPPORTED)
            return action_result.get_status()

        config = self.get_config()
        passwd = config.get(SSH_JSON_PASSWORD, None)
        root = config.get(SSH_JSON_ROOT, False)
        if root:
            passwd = None
        if not root and passwd is None:
            return action_result.set_status(phantom.APP_ERROR, SSH_ERR_NEED_PW_FOR_ROOT)
        chain = param[SSH_JSON_CHAIN]
        number = param[SSH_JSON_NUMBER]

        cmd = "sudo -S iptables -D {} {}".format(chain, number)

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd)

        if (phantom.is_fail(status_code)):
            return action_result.get_status()

        if (exit_status):
            action_result.set_status(phantom.APP_ERROR, "Shell returned an error: \"{}\"".format(stdout))
            action_result.add_data({"output": stdout})
            return action_result.get_status()

        action_result = self._save_iptables(action_result, passwd)

        return action_result.get_status()

    def _save_iptables(self, action_result, passwd):
        """ iptables needs to be saved after a command modifies it
        """
        cmd = "sudo -S service iptables save"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd)

        if (phantom.is_fail(status_code)):
            return action_result

        action_result = self._output_for_exit_status(action_result, exit_status,
                stdout + " Is the iptables service running?", SSH_SHELL_NO_ERRORS)

        return action_result

    def _get_file(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code, uname_str = self._start_connection(endpoint)
        if (phantom.is_fail(status_code)):
            action_result.set_status(self.get_status(), self.get_status_message())
            return action_result.get_status()
        self.debug_print("ssh uname", uname_str)

        file_path = param[SSH_JSON_FILE_PATH]
        # /some/dir/file_name
        file_name = file_path.split('/')[-1]
        vault_path = "/vault/tmp/{}".format(file_name)

        sftp = self._ssh_client.open_sftp()
        try:
            sftp.get(file_path, vault_path)
        except Exception as e:
            sftp.close()
            action_result.set_status(phantom.APP_ERROR, "Error getting file", e)
            return action_result.get_status()

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
        status_code, uname_str = self._start_connection(endpoint)
        if phantom.is_fail(status_code):
            action_result.set_status(self.get_status(), self.get_status_message())
            return action_result.get_status()
        self.debug_print('ssh uname', uname_str)
        
        #phantom vault file path
        file_path = Vault.get_file_path(param[SSH_JSON_VAULT_ID])
        self.debug_print('phantom vault file path', file_path)
        #phantom vault file name
        dest_file_name = Vault.get_file_info(vault_id=param[SSH_JSON_VAULT_ID])[0]['name']
        destination_path = (
            param[SSH_JSON_FILE_DEST] 
            + ('/' if param[SSH_JSON_FILE_DEST][-1] != '/' else '') 
            + dest_file_name
        )
        self.debug_print('destination_path', destination_path)
        
        sftp = self._ssh_client.open_sftp()
        try:
            sftp.put(file_path, destination_path)
        except Exception as e:
            sftp.close()
            action_result.set_status(phantom.APP_ERROR, 'Error putting file', e)
            return action_result.get_status()
        sftp.close()

        action_result.set_status(phantom.APP_SUCCESS, 'Transferred file')
        summary = {'file_sent': destination_path }
        action_result.update_summary(summary)
        return action_result.get_status()

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
        """
        """
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code, uname_str = self._start_connection(endpoint)
        if (phantom.is_fail(status_code)):
            action_result.set_status(self.get_status(), self.get_status_message())
            return action_result.get_status()

        config = self.get_config()
        passwd = config.get(SSH_JSON_PASSWORD, None)
        root = config.get(SSH_JSON_ROOT, False)
        if root:
            passwd = None

        cmd = "df -hP"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd)

        if (phantom.is_fail(status_code)):
            return action_result.get_status()

        if (exit_status):
            action_result.set_status(phantom.APP_ERROR, "Shell returned an error: \"{}\"".format(stdout))
            action_result.add_data({"output": stdout})
            return action_result.get_status()

        stdout2 = stdout.replace("%","")  # clean up % from text
        result = self._parse_generic(data=stdout2,
                   headers=['Filesystem', 'Size', 'Used', 'Avail', 'Use%', 'Mounted on'],
                   newline='\n')
        action_result.add_data(result)

        return action_result.get_status()

    def _get_memory_usage(self, param):
        """
        """
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        endpoint = param[SSH_JSON_ENDPOINT]
        status_code, uname_str = self._start_connection(endpoint)
        if (phantom.is_fail(status_code)):
            action_result.set_status(self.get_status(), self.get_status_message())
            return action_result.get_status()

        config = self.get_config()
        passwd = config.get(SSH_JSON_PASSWORD, None)
        root = config.get(SSH_JSON_ROOT, False)
        if root:
            passwd = None

        cmd = "free -h"

        status_code, stdout, exit_status = self._send_command(cmd, action_result, passwd=passwd)

        if (phantom.is_fail(status_code)):
            return action_result.get_status()

        if (exit_status):
            action_result.set_status(phantom.APP_ERROR, "Shell returned an error: \"{}\"".format(stdout))
            action_result.add_data({"output": stdout})
            return action_result.get_status()

        result = self._parse_generic(data=stdout,
                       headers=['', 'total', 'used', 'free', 'shared', 'buff/cache', "available"],
                       newline='\n', best_fit=False,
                       new_header_names=['Type', 'Total', 'Used', 'Free', 'Shared', 'Buff/Cache', 'Available'])
        action_result.add_data(result)

        return action_result.get_status()

    # Close shh client
    def _cleanup(self):
        if (self._ssh_client):
            self._ssh_client.close()

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)
        elif (action_id == self.ACTION_ID_EXEC_COMMAND):
            ret_val = self._exec_command(param)
        elif (action_id == self.ACTION_ID_REBOOT_SERVER):
            ret_val = self._reboot_server(param)
        elif (action_id == self.ACTION_ID_SHUTDOWN_SERVER):
            ret_val = self._shutdown_server(param)
        elif (action_id == self.ACTION_ID_LIST_PROCESSES):
            ret_val = self._list_processes(param)
        elif (action_id == self.ACTION_ID_TERMINATE_PROCESS):
            ret_val = self._kill_process(param)
        elif (action_id == self.ACTION_ID_LOGOUT_USER):
            ret_val = self._logout_user(param)
        elif (action_id == self.ACTION_ID_LIST_CONN):
            ret_val = self._list_connections(param)
        elif (action_id == self.ACTION_ID_LIST_FW_RULES):
            ret_val = self._list_fw_rules(param)
        elif (action_id == self.ACTION_ID_BLOCK_IP):
            ret_val = self._block_ip(param)
        elif (action_id == self.ACTION_ID_DELETE_FW_RULE):
            ret_val = self._delete_fw_rule(param)
        elif (action_id == self.ACTION_ID_GET_FILE):
            ret_val = self._get_file(param)
        elif (action_id == self.ACTION_ID_GET_MEMORY_USAGE):
            ret_val = self._get_memory_usage(param)
        elif (action_id == self.ACTION_ID_GET_DISK_USAGE):
            ret_val = self._get_disk_usage(param)
        elif (action_id == self.ACTION_ID_PUT_FILE):
            ret_val = self._put_file(param)

        self._cleanup()

        return ret_val

if __name__ == '__main__':

    # import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SshConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
