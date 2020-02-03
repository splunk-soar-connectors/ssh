# File: phssh_consts.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
# ---------------
# Phantom ssh app
# ---------------

SSH_JSON_DEVICE = "device"
SSH_JSON_USERNAME = "username"
SSH_JSON_ROOT = "root"
SSH_JSON_PASSWORD = "password"
SSH_JSON_RSA_KEY = "rsa_key_file"

SSH_JSON_ENDPOINT = "ip_hostname"
SSH_JSON_PID = "pid"
SSH_JSON_USER = "user_name"
SSH_JSON_UID = "uid"
SSH_JSON_CMD = "command"
SSH_JSON_SCRIPT_FILE = "script_file"
SSH_JSON_EXCL_ROOT = "exclude_root"
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
SSH_JSON_VAULT_ID = 'vault_id'
SSH_JSON_FILE_DEST = 'file_destination'

SSH_ERR_CONNECTION_FAILED = "Could not establish ssh connection to server"
SSH_ERR_READ_FROM_SERVER_FAILED = "Read from device failed"
SSH_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
SSH_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
SSH_ERR_NO_CONNECTION_ABORT = "Couldn't establish connection with server. Action aborted"
SSH_ERR_SHELL_SEND_COMMAND = "On device execution of command '{}' failed"
SSH_SUCC_CMD_EXEC = "Successfully executed command"
SSH_ERR_FIREWALL_CMDS_NOT_SUPPORTED = "Firewall actions are not supported for OS X"
SSH_ERR_NEED_PW_FOR_ROOT = "Unable to run commands that require root without a specified password"
SSH_PARSE_HEADER_ERR = "Provided headers do not match columns in data! Headers: {}-{} - Data: {}-{}"

SSH_UNABLE_TO_PARSE_OUTPUT_OF_CMD = "Could not parse output of command '{}'"
SSH_SHELL_NO_ERRORS = "Shell returned no errors"
SSH_ERR_CMD_ERRORS = "Command executed but shell returned errors"
SSH_SUCC_CMD_SUCCESS = "Command successfully executed and shell returned no errors"
