[comment]: # "Auto-generated SOAR connector documentation"
# SSH

Publisher: Splunk  
Connector Version: 2\.3\.8  
Product Vendor: Generic  
Product Name: SSH  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This app supports executing various endpoint\-based investigative and containment actions on an SSH endpoint

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
**Note:** This app will only support Linux distributions and Mac OS X. The app internally uses the
Paramiko module to establish an SSH connection with the server, and per the official Paramiko
documentation, it does not support non-standard SSH implementations or host systems. See [this
link](http://www.paramiko.org/faq.html#paramiko-doesn-t-work-with-my-cisco-windows-or-other-non-unix-system)
for more details.

## Root access permissions

If you are logging in as the root user (or a user otherwise configured to not need to use sudo),
then be sure to check the "User is root" box in the asset configuration. Otherwise, you will have to
provide a password if you want to run commands that require root access even if the RSA key is
specified, as required by your sudoers configuration. If you incorrectly specify that the account is
root, or if you incorrectly enter a password in conjunction with the RSA key, then the action may
indefinitely hang.

## Pseudo-terminal

In certain scenarios, it may be necessary to enable the pseudo-terminal for `     sudo    ` commands
where **requiretty** is enabled in the sudoers config. In that case, you can:

-   disable the **requiretty** requirement on the server-side or
-   enable pseudo-terminal in your asset config.

However, if it is not required, it should be disabled. Otherwise, the app may hang indefinitely when
used with servers where pseudo-terminals are not supported.

## Key-based authentication

Refer to the following steps to install the authentication keys. Note that the key pair must be
unencrypted and generated using `     ssh-keygen    ` .

**Note:** The screenshots attached below are for Non-NRI instances having **/home/phantom-worker**
as the home directory. For NRI instances, consider **/home/phanru** as the home directory and
**phanru** as the user. If you are using different user, then consider **/home/{your_user_name}** as
the home directory and **{your_user_name}** as the user. The steps would remain the same with only a
minor change that the user would be **phanru** or **{your_user_name}** instead of **phantom-worker**
.

1.  Connect to your Phantom instance and sudo to root. Change the current directory to
    phantom-worker's home directory using `       cd /home/phantom-worker/      `  

    [![](img/1.png)](img/1.png)

2.  Create a directory for the SSH keys (NOTE: You must give it the name .ssh). If you already have
    a key pair, move the private key files into this directory. In this case, the file
    `       id_rsa      ` has been added to the user's home directory using scp.

    [![](img/2.png)](img/2.png)

      
    It is entirely possible to generate a new key pair from the Phantom VM. To generate the key
    using `       ssh-keygen      ` , refer to the following steps:

    -   Generate a new key pair using the command `        ssh-keygen -f .ssh/id_rsa       `
    -   Once an SSH key pair has been generated, the ssh-copy-id command can be used to install it
        as an authorized key on the server. Use the command
        `        ssh-copy-id -i .ssh/id_rsa <user>@<host>       ` . Here, the \<user> and \<host>
        refer to the SSH server where you want to execute the SSH commands/Phantom actions. The
        command may request a password or other authentication for the server.

    The RSA public key is successfully added to the server.

3.  Once the files are in the correct place, the ownership of the .ssh directory needs to be set
    using `      chown -R phantom-worker:phantom-worker .ssh     ` . To verify whether the owner of
    the .ssh folder is successfully updated or not use the `      ls -lAR     ` command.  
    [![](img/3.png)](img/3.png)

      
    Using the `       chown      ` command:  

    [![](img/4.png)](img/4.png)

The RSA key should be ready to use in the SSH asset. Based on the above example, configure this by
specifying 'id_rsa' as the RSA key file. In the case of a different user, the absolute path to the
key must be specified. For example, if keys are added using username **testuser** having the home
directory **/home/testuser** then **/home/testuser/.ssh/id_rsa** should be specified as the RSA key
file.

## Verify Last Reboot Time

After successfully logging into your SSH server, run the command `     last reboot    ` which will
display all the previous reboot dates and times for the system.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a SSH asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**username** |  required  | string | Username
**root** |  optional  | boolean | User is root
**password** |  optional  | password | Password
**rsa\_key\_file** |  optional  | string | RSA Key file
**ip\_hostname** |  optional  | string | Device IP/Hostname \(for test connectivity only\)
**timeout** |  optional  | numeric | Seconds before timeout \(will be applicable for all actions\)
**pseudo\_terminal** |  optional  | boolean | Enable pseudo\-terminal when running sudo commands

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validates endpoint connection  
[execute program](#action-execute-program) - Executes a program on the remote machine  
[list connections](#action-list-connections) - Lists all the network connections\. Requires root privileges\. Requires netstat to be installed  
[block ip](#action-block-ip) - Add an iptables rule to the Linux server\. Requires root privileges\. Not supported on OS X  
[list firewall rules](#action-list-firewall-rules) - Lists the rules in iptables\. Requires root privileges\. Not supported on OS X  
[delete firewall rule](#action-delete-firewall-rule) - Delete a firewall rule\. Requires root privileges\. Not supported on OS X  
[reboot system](#action-reboot-system) - Reboot the endpoint \(Requires root privileges\)  
[shutdown system](#action-shutdown-system) - Shutdown the endpoint\(Requires root privileges\)  
[terminate process](#action-terminate-process) - Terminate a process \(Requires root privileges\)  
[logoff user](#action-logoff-user) - Logout a user on endpoint \(Requires root privileges\)  
[list processes](#action-list-processes) - List processes on endpoint  
[get disk usage](#action-get-disk-usage) - Retrieve disk usage from endpoint  
[get memory usage](#action-get-memory-usage) - Retrieve memory usage from endpoint  
[get file](#action-get-file) - Retrieve a file from the endpoint and save it to the vault  
[put file](#action-put-file) - Put a file from the vault to another location  

## action: 'test connectivity'
Validates endpoint connection

Type: **test**  
Read only: **False**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'execute program'
Executes a program on the remote machine

Type: **generic**  
Read only: **False**

Please provide a value for the 'timeout' parameter when executing continuous commands such as 'ping' so that the action does not keep running indefinitely\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP to execute command on | string |  `ip`  `host name` 
**command** |  optional  | Command to be executed on endpoint | string | 
**script\_file** |  optional  | Local path to shell script | string | 
**timeout** |  optional  | Seconds before timeout\. If an invalid value or 0 is entered, the timeout specified in the asset configuration will be used \(default\: 0\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.command | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.script\_file | string | 
action\_result\.parameter\.timeout | numeric | 
action\_result\.data\.\*\.output | string | 
action\_result\.summary\.exit\_status | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list connections'
Lists all the network connections\. Requires root privileges\. Requires netstat to be installed

Type: **investigate**  
Read only: **True**

Executes the following command<br><code>sudo \-S netstat \-etnp</code><br>On OS X the following command is executed instead<br><code>sudo \-S  lsof \-nP \-i</code><br>Note that the name of the command in the output is limited to 9 characters\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP to list network connections on | string |  `ip`  `host name` 
**local\_addr** |  optional  | Local IP to filter on | string |  `ip` 
**local\_port** |  optional  | Local port to match | numeric |  `port` 
**remote\_addr** |  optional  | Remote IP to filter on | string |  `ip` 
**remote\_port** |  optional  | Remote port to match | numeric |  `port` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.local\_addr | string |  `ip` 
action\_result\.parameter\.local\_port | numeric |  `port` 
action\_result\.parameter\.remote\_addr | string |  `ip` 
action\_result\.parameter\.remote\_port | numeric |  `port` 
action\_result\.data\.\*\.connections\.\*\.cmd | string | 
action\_result\.data\.\*\.connections\.\*\.inode | string | 
action\_result\.data\.\*\.connections\.\*\.local\_ip | string |  `ip` 
action\_result\.data\.\*\.connections\.\*\.local\_port | string |  `port` 
action\_result\.data\.\*\.connections\.\*\.pid | string |  `pid` 
action\_result\.data\.\*\.connections\.\*\.protocol | string | 
action\_result\.data\.\*\.connections\.\*\.rec\_q | string | 
action\_result\.data\.\*\.connections\.\*\.remote\_ip | string |  `ip` 
action\_result\.data\.\*\.connections\.\*\.remote\_port | string |  `port` 
action\_result\.data\.\*\.connections\.\*\.send\_q | string | 
action\_result\.data\.\*\.connections\.\*\.state | string | 
action\_result\.data\.\*\.connections\.\*\.uid | string | 
action\_result\.summary\.exit\_status | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block ip'
Add an iptables rule to the Linux server\. Requires root privileges\. Not supported on OS X

Type: **contain**  
Read only: **False**

Need to specify either an IP or a port to block\.<br>Executes the following command<br><code>sudo \-S iptables \-I &lt;DIRECTION&gt; \-p &lt;PROTOCOL&gt; &lt;IP&gt; &lt;PORT&gt; \-j DROP \-m &lt;COMMENT&gt;</code><br>where the IP and PORT fields will block either source or destination based on the DIRECTION\.<br>Only iptables is supported\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP to add firewall rule to | string |  `ip`  `host name` 
**remote\_ip** |  optional  | Remote IP to block | string |  `ip`  `host name` 
**remote\_port** |  optional  | Remote port to block | numeric |  `port` 
**protocol** |  required  | Protocol to block | string | 
**direction** |  required  | Inbound or outbound | string | 
**comment** |  optional  | Leave a comment | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.direction | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.protocol | string | 
action\_result\.parameter\.remote\_ip | string |  `ip`  `host name` 
action\_result\.parameter\.remote\_port | numeric |  `port` 
action\_result\.data\.\*\.output | string | 
action\_result\.summary\.exit\_status | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list firewall rules'
Lists the rules in iptables\. Requires root privileges\. Not supported on OS X

Type: **investigate**  
Read only: **True**

Executes the following command<br><code>sudo \-S iptables \-L &lt;CHAIN&gt; \-\-line\-numbers \-n</code><br>Only iptables is supported\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP to list firewall rules on | string |  `ip`  `host name` 
**protocol** |  optional  | Protocol to match | string | 
**port** |  optional  | Port to match | numeric |  `port` 
**chain** |  optional  | Chain to match \(INPUT, OUTPUT, etc\.\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.chain | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.port | numeric |  `port` 
action\_result\.parameter\.protocol | string | 
action\_result\.data\.\*\.rules\.\*\.chain | string | 
action\_result\.data\.\*\.rules\.\*\.destination | string | 
action\_result\.data\.\*\.rules\.\*\.num | string | 
action\_result\.data\.\*\.rules\.\*\.options | string | 
action\_result\.data\.\*\.rules\.\*\.protocol | string | 
action\_result\.data\.\*\.rules\.\*\.source | string | 
action\_result\.data\.\*\.rules\.\*\.target | string | 
action\_result\.summary\.exit\_status | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete firewall rule'
Delete a firewall rule\. Requires root privileges\. Not supported on OS X

Type: **correct**  
Read only: **False**

Executes the following command<br><code>sudo \-S iptables \-D &lt;CHAIN&gt; &lt;NUMBER&gt;</code><br>Only iptables is supported\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP of endpoint | string |  `ip`  `host name` 
**chain** |  required  | Name of chain \(INPUT, OUTPUT, etc\.\) | string | 
**number** |  required  | Number of rule to delete | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.chain | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.number | numeric | 
action\_result\.data\.\*\.output | string | 
action\_result\.summary\.exit\_status | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'reboot system'
Reboot the endpoint \(Requires root privileges\)

Type: **contain**  
Read only: **False**

Executes the following command<br><code>sudo \-S shutdown \-r now</code>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP of server to reboot | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data\.\*\.output | string | 
action\_result\.summary\.exit\_status | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'shutdown system'
Shutdown the endpoint\(Requires root privileges\)

Type: **contain**  
Read only: **False**

Executes the following command<br><code>sudo \-S shutdown \-h now</code>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP of server to shutdown | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data\.\*\.output | string | 
action\_result\.summary\.exit\_status | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'terminate process'
Terminate a process \(Requires root privileges\)

Type: **contain**  
Read only: **False**

Executes the following command<br><code>sudo \-S kill \-SIGKILL &lt;PID&gt;</code>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP of endpoint | string |  `ip`  `host name` 
**pid** |  required  | PID of process to terminate | numeric |  `pid` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.pid | numeric |  `pid` 
action\_result\.data\.\*\.output | string | 
action\_result\.summary\.exit\_status | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'logoff user'
Logout a user on endpoint \(Requires root privileges\)

Type: **contain**  
Read only: **False**

Executes the following command<br><code>sudo \-S pkill \-SIGKILL &lt;USER\_NAME&gt;</code><br>This will terminate any sessions with this user as well as any other processes which they are running\. Be careful when running this with certain users \(i\.e\. root\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP of endpoint | string |  `ip`  `host name` 
**user\_name** |  required  | Name of user to logout | string |  `user name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.user\_name | string |  `user name` 
action\_result\.data\.\*\.output | string | 
action\_result\.summary\.exit\_status | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list processes'
List processes on endpoint

Type: **investigate**  
Read only: **True**

Executes the following command<br><code>ps c \-Ao user,uid,pid,ppid,stime,command</code>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP of endpoint | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data\.\*\.processes\.\*\.command | string | 
action\_result\.data\.\*\.processes\.\*\.pid | string |  `pid` 
action\_result\.data\.\*\.processes\.\*\.ppid | string |  `pid` 
action\_result\.data\.\*\.processes\.\*\.stime | string | 
action\_result\.data\.\*\.processes\.\*\.uid | string | 
action\_result\.data\.\*\.processes\.\*\.user | string |  `user name` 
action\_result\.summary\.exit\_status | numeric | 
action\_result\.summary\.total\_processes | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get disk usage'
Retrieve disk usage from endpoint

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP to execute command on | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data\.\*\.\*\.Avail | string | 
action\_result\.data\.\*\.\*\.Filesystem | string | 
action\_result\.data\.\*\.\*\.Mounted on | string | 
action\_result\.data\.\*\.\*\.Size | string | 
action\_result\.data\.\*\.\*\.Use% | string | 
action\_result\.data\.\*\.\*\.Used | string | 
action\_result\.data\.\*\.\*\.raw | string | 
action\_result\.summary\.exit\_status | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get memory usage'
Retrieve memory usage from endpoint

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP to execute command on | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data\.\*\.\*\.Available | string | 
action\_result\.data\.\*\.\*\.Buff/Cache | string | 
action\_result\.data\.\*\.\*\.Free | string | 
action\_result\.data\.\*\.\*\.Shared | string | 
action\_result\.data\.\*\.\*\.Total | string | 
action\_result\.data\.\*\.\*\.Type | string | 
action\_result\.data\.\*\.\*\.Used | string | 
action\_result\.data\.\*\.\*\.raw | string | 
action\_result\.summary\.exit\_status | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get file'
Retrieve a file from the endpoint and save it to the vault

Type: **investigate**  
Read only: **True**

The file path needs to be an absolute path\. For example, <b>/home/USER/file\.tgz</b> instead of <b>~/file\.tgz</b>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP to execute command on | string |  `ip`  `host name` 
**file\_path** |  required  | Full path of the file to download \(include filename\) | string |  `file path` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_path | string |  `file path` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data | string | 
action\_result\.summary\.exit\_status | numeric | 
action\_result\.summary\.name | string | 
action\_result\.summary\.size | numeric | 
action\_result\.summary\.vault\_id | string |  `vault id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'put file'
Put a file from the vault to another location

Type: **generic**  
Read only: **False**

The file path needs to be an absolute path\. For example, <b>/home/USER/</b> instead of <b>~/USER</b>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP to execute command on | string |  `ip`  `host name` 
**vault\_id** |  required  | Vault ID of file | string |  `vault id` 
**file\_destination** |  required  | File destination path \(exclude filename\) | string |  `file path` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_destination | string |  `file path` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.vault\_id | string |  `vault id` 
action\_result\.data | string | 
action\_result\.summary\.file\_sent | string |  `file path` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 