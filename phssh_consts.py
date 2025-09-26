# File: phssh_consts.py
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
# Phantom ssh app
# action ids
ACTION_ID_EXEC_COMMAND = "ssh_execute_command"
ACTION_ID_REBOOT_SERVER = "ssh_reboot_server"
ACTION_ID_SHUTDOWN_SERVER = "ssh_shutdown_server"
ACTION_ID_LIST_PROCESSES = "ssh_list_processes"
ACTION_ID_TERMINATE_PROCESS = "ssh_kill_process"
ACTION_ID_LOGOUT_USER = "ssh_logout_user"
ACTION_ID_LIST_FW_RULES = "ssh_list_fw_rules"
ACTION_ID_BLOCK_IP = "ssh_block_ip"
ACTION_ID_DELETE_FW_RULE = "ssh_delete_fw_rule"
ACTION_ID_LIST_CONNECTIVITY = "ssh_list_conn"
ACTION_ID_GET_FILE = "ssh_get_file"
ACTION_ID_GET_MEMORY_USAGE = "get_memory_usage"
ACTION_ID_GET_DISK_USAGE = "get_disk_usage"
ACTION_ID_PUT_FILE = "ssh_put_file"

OS_LINUX = 0
OS_MAC = 1

# Timeouts in seconds
FIRST_RECV_TIMEOUT = 30
SEND_TIMEOUT = 2

SSH_JSON_DEVICE = "ip_hostname"
SSH_JSON_USERNAME = "username"
SSH_JSON_ROOT = "root"
SSH_JSON_PASSWORD = "password"  # pragma: allowlist secret
SSH_JSON_RSA_KEY = "rsa_key_file"

SSH_JSON_ENDPOINT = "ip_hostname"
SSH_JSON_PID = "pid"
SSH_JSON_USER = "user_name"
SSH_JSON_CMD = "command"
SSH_JSON_SCRIPT_FILE = "script_file"
SSH_JSON_LOCAL_ADDR = "local_addr"
SSH_JSON_LOCAL_PORT = "local_port"
SSH_JSON_REMOTE_ADDR = "remote_addr"
SSH_JSON_REMOTE_PORT = "remote_port"
SSH_JSON_PROTOCOL = "protocol"
SSH_JSON_PORT = "port"
SSH_JSON_CHAIN = "chain"
SSH_JSON_REMOTE_IP = "remote_ip"
SSH_JSON_DIRECTION = "direction"
SSH_JSON_COMMENT = "comment"
SSH_JSON_NUMBER = "number"
SSH_JSON_FILE_PATH = "file_path"
SSH_JSON_TIMEOUT = "timeout"
SSH_JSON_PSEUDO_TERMINAL = "pseudo_terminal"
SSH_JSON_POWERBROKER = "powerbroker"
SSH_JSON_VAULT_ID = "vault_id"
SSH_JSON_FILE_DEST = "file_destination"
SSH_JSON_DISABLE_SHA2 = "disable_sha2"

SSH_CONNECTIVITY_FAILED_ERR = "Could not establish SSH connection to server"
SSH_CONNECTIVITY_ESTABLISHED = "Established SSH connection to server"
SSH_CONNECTIVITY_TEST_ERR = "Test Connectivity failed"
SSH_SUCCESS_CONNECTIVITY_TEST = "Test Connectivity passed"
SSH_SHELL_SEND_COMMAND_ERR = "On device execution of command '{}' failed"
SSH_SUCCESS_CMD_EXEC = "Successfully executed command"
SSH_FIREWALL_CMDS_NOT_SUPPORTED_ERR = "Firewall actions are not supported for OS X"
SSH_NEED_PW_FOR_ROOT_ERR = "Unable to run commands that require root without a specified password"
SSH_PARSE_HEADER_ERR = "Provided headers do not match columns in data! Headers: {}-{} - Data: {}-{}"

SSH_UNABLE_TO_PARSE_OUTPUT_OF_CMD = "Could not parse output of command '{}'"
SSH_SHELL_NO_ERR = "Shell returned no errors"
SSH_IS_NETSTAT_INSTALLED_MSG = "Is netstat installed?"
SSH_SUCCESS_CMD_SUCCESS = "Command successfully executed and shell returned no errors"
SSH_NO_SHELL_OUTPUT_MSG_ERR = "Shell returned an error. No shell output returned"
SSH_SHELL_OUTPUT_MSG_ERR = "Shell returned an error. Shell output: '{stdout}'"
SSH_PY_2TO3_MSG_ERR = "Error occurred while handling python 2to3 compatibility for the input string"
SSH_AUTHENTICATION_FAILED_MSG_ERR = "Authentication failed, please verify your credentials"
SSH_BAD_HOST_KEY_MSG_ERR = "Unable to verify server's host key"
SSH_FAILED_TO_RESOLVE_MSG_ERR = "Error occurred while resolving '{server}'"
SSH_DECODE_OUTPUT_MSG_ERR = "Error occurred while decoding the output"
SSH_UNABLE_TO_READ_SCRIPT_FILE_MSG_ERR = "Error occurred while reading '{script_file}' script file"
SSH_COMMAND_OR_SCRIPT_FILE_NOT_PROVIDED_MSG_ERR = "Please provide either a 'command' or 'script_file' to be executed on endpoint"
SSH_VERIFY_LAST_REBOOT_TIME_MSG = "Please refer the docs to verify the last reboot time"
SSH_ENDPOINT_SHUTDOWN_MSG = "Endpoint successfully shutdown"
SSH_PWD_OR_RSA_KEY_NOT_SPECIFIED_MSG_ERR = "Please specify either a password or RSA key to establish the connection"  # pragma: allowlist secret
SSH_HOSTNAME_OR_IP_NOT_SPECIFIED_MSG_ERR = "Please specify either a hostname or IP to establish the connection"
SSH_REMOTE_IP_OR_PORT_NOT_SPECIFIED_MSG_ERR = "Please specify either a remote ip or port to block"
SSH_PID_TERMINATED_MSG = "Successfully terminated pid {pid}"
SSH_FETCHING_PYTHON_VERSION_MSG_ERR = "Error occurred while fetching the Phantom server's Python major version"
SSH_LOGOFF_USER_MSG = "Successfully logged off user: '{username}'"
SSH_GET_FILE_MSG_ERR = "Error getting file. {err}"
SSH_UNABLE_TO_RETREIVE_VAULT_ITEM_MSG_ERR = "Unable to retreive vault item details"
SSH_PUT_FILE_MSG_ERR = "Error putting file. {err}"
SSH_EXCLUDE_FILENAME_MSG_ERR = "Error: Do not include filename in the file destination"
SSH_FILE_NOT_FOUND_MSG_ERR = "Please verify that the provided file destination exists and make sure the filename is not included in it"
SSH_ASSET_TIMEOUT_MSG = "Considering the timeout value from the asset configuration"

# constants relating to 'get_error_message_from_exception'
SSH_MSG_UNAVAILABLE_ERR = "Error message unavailable. Please check the asset configuration and|or action parameters."
SSH_CODE_UNAVAILABLE_ERR = "Error code unavailable"
SSH_UNICODE_DAMMIT_TYPE_MSG_ERR = (
    "Error occurred while connecting to the SSH server. ",
    "Please check the asset configuration and|or the action parameters.",
)

# constants relating to 'validate_integer'
SSH_VALID_INT_MSG = "Please provide a valid integer value in the '{param}' parameter"
SSH_NON_NEG_NON_ZERO_INT_MSG = "Please provide a valid non-zero positive integer value in the '{param}' parameter"
SSH_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the '{param}' parameter"
