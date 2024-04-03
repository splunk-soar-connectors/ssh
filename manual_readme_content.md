[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2024 Splunk Inc."
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

Refer to the following steps to install the authentication keys in on-prem instance. Note that the
key pair must be unencrypted and generated using `     ssh-keygen    ` .

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

## Disable SHA2 Algorithms Parameter

The 'disable_sha2' parameter in the asset can be checked when the SSH instance is old one which does
not have the support of either RSA2 or the "server-sig-algs" protocol extension.

## Verify Last Reboot Time

After successfully logging into your SSH server, run the command `     last reboot    ` which will
display all the previous reboot dates and times for the system.
