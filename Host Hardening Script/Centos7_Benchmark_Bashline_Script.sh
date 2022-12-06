#!/bin/bash
##Filename:     CentOS_Benchmark_Bashline_Script.sh
##Date:         2021-08-11
##Description:  Security detection script

echo "##########################################################################"
echo "#                                                                        #"
echo "#                   Benchmark Bashline Security script                   #"
echo "#                                                                        #"
echo "#Warning: This script is only a check operation and does not make any    #"
echo "#changes to the server. Administrators can make security changes based   #"
echo "#on this report                                                          #"
echo "#                                                                        #"
echo "##########################################################################"

echo " "
echo "##########################################################################"
echo "#                                                                        #"
echo "#                      Centos 7   Host security check                    #"
echo "#                                                                        #"
echo "##########################################################################"
#
#################################################################################
echo "====================================OS Detection check===================="
#################################################################################
#
hostname=$(uname -n)
system=$(cat /etc/os-release | grep "^NAME" | awk -F\" '{print $2}')
version=$(cat /etc/redhat-release | awk '{print $4$5}')
kernel=$(uname -r)
platform=$(uname -p)
address=$(ip addr | grep inet | grep -v "inet6" | grep -v "127.0.0.1" | awk '{ print $2; }' | tr '\n' '\t' )
cpumodel=$(cat /proc/cpuinfo | grep name | cut -f2 -d: | uniq)
cpu=$(cat /proc/cpuinfo | grep 'processor' | sort | uniq | wc -l)
machinemodel=$(dmidecode | grep "Product Name" | sed 's/^[ \t]*//g' | tr '\n' '\t' )
date=$(date)

echo "hostname:           $hostname"
echo "systemname:         $system"
echo "version:            $version"
echo "kernel:             $kernel"
echo "platform:           $platform"
echo "address:            $address"
echo "CPU-model:          $cpumodel"
echo "CPU-core:           $cpu"
echo "machinemodel:       $machinemodel"
echo "date:               $date"
echo " "
#################################################################################
echo   "==============================Resouce Usage============================="
#################################################################################
summemory=$(free -h |grep "Mem:" | awk '{print $2}')
freememory=$(free -h |grep "Mem:" | awk '{print $4}')
usagememory=$(free -h |grep "Mem:" | awk '{print $3}')
uptime=$(uptime | awk '{print $2" "$3" "$4" "$5}' | sed 's/,$//g')
loadavg=$(uptime | awk '{print $9" "$10" "$11" "$12" "$13}')

echo "unsigned long totalhigh:           $summemory"
echo "Used memory size:                  $usagememory"
echo "Available memory size:       $freememory"
echo "system uptime:         $uptime"
echo "system load:             $loadavg"
#################################################################################
echo   "============================Performance usage checking=================="
#################################################################################
echo "Memory status:"
vmstat 2 5
echo "zombie process:"
ps -ef | grep zombie | grep -v grep
if [ $? == 1 ];then
    echo ">>>Zombie free process"
else
    echo ">>>There are zombie processes ------[to be adjusted]"
fi

echo "The process that consumes the most CPU:"
ps auxf |sort -nr -k 3 |head -5

echo "The most memory-consuming process:"
ps auxf |sort -nr -k 4 |head -5

echo  "environment variable:"
env

echo  "routing:"
route -n

echo  "listener port:"
netstat -tunlp

echo  "The currently established connection:"
netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}'

echo "Start the service:"
systemctl list-unit-files | grep enabled
echo " "


echo "Display patition table:"
echo "If the disk space usage is too high, adjust the disk space usage in time---------[needed adjustment]"
df -h
echo "=============================dividing line================================"
echo "Available block device information:"
lsblk
echo "=============================dividing line================================"
echo "File System:"
more /etc/fstab  | grep -v "^#" | grep -v "^$"
echo " "

#################################################################################
echo   "=========================System Userse checking========================="
#################################################################################
echo  "active users:"
w | tail -n +2
echo "=========================================================================="
echo  "userlist:"
cut -d: -f1,2,3,4 /etc/passwd
echo "=========================================================================="
echo  "All system groups:"
cut -d: -f1,2,3 /etc/group
echo "=========================================================================="
echo  "Scheduled tasks of the current user:"
crontab -l
echo " "

#################################################################################
echo "===================Identity security checking=============================="
#################################################################################
grep -i "^password.*requisite.*pam_cracklib.so" /etc/pam.d/system-auth  > /dev/null
if [ $? == 0 ];then
    echo ">>>Password complexity: Set"
else
    grep -i "pam_pwquality\.so" /etc/pam.d/system-auth > /dev/null
    if [ $? == 0 ];then
  echo ">>>Password complexity: Set"
    else
  echo ">>>Password complexity: not set. Harden the password --------[needed adjustment]"
    fi
fi

echo "=============================lock user checking==========================="

awk -F":" '{if($2!~/^!|^*/){print ">>>("$1")" " Yes Is an unlocked account. Ask the administrator to check whether the account is suspicious--------[needed adjustment]"}}' /etc/shadow

echo "=============================Password expiration checking================="

more /etc/login.defs | grep -E "PASS_MAX_DAYS" | grep -v "#" |awk -F' '  '{if($2!=90){print ">>>The password expiration date is "$2" days. Please change it to 90 days------[needed adjustment]"}}'
echo ''
grep -i "^auth.*required.*pam_tally2.so.*$" /etc/pam.d/sshd  > /dev/null
if [ $? == 0 ];then
  echo "Handling login failure: enabled"
else
  echo "Login failure handling: not enabled, please harden the login failure lock function ----------[needed adjustment]"
fi
echo " "


#################################################################################
echo "Access Control checking"
#################################################################################

echo "The following non-default users exist in the system:"
more /etc/passwd |awk -F ":" '{if($3>500){print ">>>/etc/passwd inside"$1 "的UID is"$3"，This account is not the default account of the system. Please check whether it is a suspicious account. --------[Needs adjusted]"}}'

echo ''
awk -F: '$3==0 {print $1}' /etc/passwd

echo ''
awk -F: '($2=="!!") {print $1"This account is an empty command account. Please check whether it is a new account. If it is a new account, please set the password -------[needed adjustment]."}' /etc/shadow


#################################################################################
echo "safety audit"
#################################################################################
systemctl status auditd.service
echo ""

echo "System Audit Logs 0640 Permissive"
ls -al  /etc/audit/auditd.conf

echo "Log in to the history record of the host within 30 days:"
last | head -n 30

echo ''
echo "Check whether the syslog audit service is enabled:"
if service rsyslog status | egrep " active \(running";then
  echo ">>>Analysis indicates that the syslog service is enabled"
else
  echo ">>>After analysis, the syslog service is disabled. You are advised to run the service rsyslog start command to enable the log audit function ---------[needed adjustment]"
fi

echo ''
echo "Check whether outgoing syslog sending is enabled:"
if more /etc/rsyslog.conf | egrep "@...\.|@..\.|@.\.|\*.\* @...\.|\*\.\* @..\.|\*\.\* @.\.";then
  echo ">>>After analysis, the outgoing syslog sending function is enabled on the client --------[Needs adjusted"
else
  echo ">>>After analysis, the outgoing syslog sending function of the client is disabled ---------[No need to adjust]"
fi

echo ''

echo "Audit elements and audit logs:"
more /etc/rsyslog.conf  | grep -v "^[$|#]" | grep -v "^$"
echo " "
echo "Modification time of key files in the system:"
ls -ltr /bin/ls /bin/login /etc/passwd  /bin/ps /etc/shadow|awk '{print ">>> filename："$9"  ""Modification Date："$6" "$7" "$8}'
echo ''
#########################################################################################################################################################
#   ls :File is a function that stores the ls command, After the file is deleted, the ls command cannot be executed .                                   #
#   login:login Is a file that controls user login,Once tampered or deleted, the system will not be able to switch users or login users.                #
#   /etc/passwd :Is a file that mainly holds user information                                                                                           #
#   /bin/ps: Process Viewing Files,If the files are damaged or changed, the ps command cannot be used                                                   #
#   /etc/shadow:/etc/passwd The shadow file where the password is stored and can only be read by the root user.                                         #
#########################################################################################################################################################

echo ' '
echo 'Check whether important log files exist:'
log_secure=/var/log/secure
log_messages=/var/log/messages
log_cron=/var/log/cron
log_boot=/var/log/boot.log
log_dmesg=/var/log/dmesg

if [ -e '$log_secure' ]; then
echo  '>>>/var/log/secure The log file exists'
else
  echo  '>>>/var/log/secure The log file does not exist------[needed adjustment]'
fi

if [ -e '$log_messages' ]; then
  echo '>>>/var/log/messages The log file exists'
else
  echo  '>>>/var/log/messages the log file does not exists------[needed adjustment]'
fi

if [ -e '$log_cron' ]; then
  echo  '>>>/var/log/cron Log file exists'
else
  echo '>>>/var/log/cron the log file does not exists--------[needed adjustment]'
fi


if [ -e '$log_boot' ]; then
  echo  '>>>/var/log/boot.logLog file exists'
else
  echo  '>>>/var/log/boot.logthe log file does not exists--------[needed adjustment]'
fi

if [ -e '$log_dmesg' ]; then
  echo  '>>>/var/log/dmesgLog file exists'
else
  echo  '>>>/var/log/dmesg the log file does not exists--------[needed adjustment]'
fi

echo ' '
######################################################################################
echo 'invade checking'
######################################################################################
echo 'System intrusion behavior:'
more /var/log/secure |grep refused
if [ $? == 0 ];then
    echo 'If there is an intrusion, analyze and handle it--------[needed adjustment]'
else
    echo 'Noninvasive behavior'
fi
echo ''
echo 'User login list error:'
lastb | head > /dev/null
if [ $? == 1 ];then
    echo 'No user error login list'
else
    echo ''User login error'--------'[needed adjustment]''
    lastb | head 
fi
echo ''
echo 'ssh Violent login information:'
more /var/log/secure | grep  'Failed' > /dev/null
if [ $? == 1 ];then
    echo 'No SSH violent login information'
else
    more /var/log/secure|awk '/Failed/{print $(NF-3)}'|sort|uniq -c|awk '{print 'IP address and number of failed login attempts: '$2'='$1'next---------[Needed adjustment]';}'
fi
echo ''


######################################################################################
echo 'malicious code checking'
######################################################################################
echo 'Check whether virus software is installed:'
crontab -l | grep clamscan.sh > /dev/null
if [ $? == 0 ];then
  echo 'The ClamAV antivirus software has been installed'
  crontab -l | grep freshclam.sh > /dev/null
  if [ $? == 0 ];then
    echo 'Periodic updates to the virus library have been deployed'
  fi
else
  echo 'The ClamAV antivirus software is not installed,Deploy the antivirus software to harden host protection--------[No needed adjustment]'
fi
echo ''

######################################################################################
echo 'Resource control checking'
######################################################################################

echo 'Check whether the xinetd service is enabled:'
if ps -elf |grep xinet |grep -v "grep xinet";then
  echo 'xinetd The service is running.Please check whether you can shut down the xinetd service--------[No needed adjustment]'
else
  echo 'xinetd The service is not enabled-------[No needed adjustment]'
fi
echo ''
echo  'Check whether the SSH service is enabled:'
if service sshd status | grep -E 'listening on|active \(running\)'; then
  echo 'SSH Service started'
else
  echo 'SSH The service is not enabled--------[needed adjustment]'
fi
echo ''
echo 'Check whether the Telnet-Server service is enabled :'
if more /etc/xinetd.d/telnetd 2>&1|grep -E 'disable=no'; then
  echo 'Telnet-Server Service started'
else
  echo 'Telnet-Server service is not enabled--------[No needed adjustment]'
fi

echo ''

ps axu | grep iptables | grep -v grep || ps axu | grep firewalld | grep -v grep 
if [ $? == 0 ];then
  echo 'Firewall is enabled'
iptables -nvL --line-numbers
else
  echo 'Firewall is disabled--------[needed adjustment]'
fi
echo ''

echo  'View the SSH remote access policy (host. Deny deny list):'
if more /etc/hosts.deny | grep -E "sshd"; then
  echo 'The remote access policy has been set--------[needed adjustment]'
else
  echo 'The remote access policy is not set--------[No needed adjustment]'
fi

echo ''

echo 'View the list of SSH remote access policies (hosts.allow):'
if more /etc/hosts.allow | grep -E 'sshd'; then
  echo 'The remote access policy has been set--------[needed adjustment]'
else
  echo 'The remote access policy is not set--------[No needed adjustment]'
fi

grep -i 'TMOUT' /etc/profile /etc/bashrc
if [ $? == 0 ];then
    echo 'The login timeout limit has been set'
else
    echo 'The login timeout limit is not set. Set it by adding the TMOUT parameter in /etc/profile or /etc/bashrc=600 --------[needed adjustment]'
fi

######################################################################################
echo "Checking ssh  checking"
######################################################################################
echo ''
echo 'checking PermitEmptyPasswords'
grep -i 'PermitEmptyPasswords' /etc/ssh/sshd_config
if [ $? == no ];then
    echo 'This SSH disables the PermitEmptyPasswords service'
else
    echo 'The PermitEmptyPasswords of SSH is not set. Set it by adding the PermitEmptyPasswords parameter in /etc/ssh/sshd_config=no --------[needed adjustment]'
fi

echo ''
echo 'checking ssh ClientAliveCountMax'

grep -i 'ClientAliveCountMax' /etc/ssh/sshd_config
if [ $? == 5 ];then
    echo 'This SSH set the ClientAliveCountMax'
else
    echo 'The ClientAliveCountMax of SSH is not set. Set it by adding the ClientAliveCountMax parameter in /etc/ssh/sshd_config=5 --------[needed adjustment]'
fi


echo ''
echo 'ssh Warning banner'
grep -i 'Banner /etc/ssh/sshd-banner' /etc/ssh/sshd_config
if [ $? == Banner ];then
    echo 'This ssh set the  Banner'
else
    echo 'The  banner of SSH is not set  . Set it by adding the ssh sshd-banner parameter in /etc/ssh/sshd_config=Banner /etc/ssh/sshd-banner --------[needed adjustment]'
fi


echo ''
echo 'SSH protocol checking'
grep -i "protocol" /etc/ssh/sshd_config
if [ $? == no ];then
    echo 'This protocol set the ssh'
else
    echo "The  protocol of SSH is not set  . Set it by adding the ssh protocol parameter in /etc/ssh/sshd_config=2  --------[needed adjustment]"
fi

echo ''
echo 'SSH ClientAliveInterval checking'
grep -i "ClientAliveInterval" /etc/ssh/sshd_config
if [ $? == 30 ];then
    echo 'This ClientAliveInterval set the ssh'
else
    echo "The ClientAliveInterval of SSH is not set.Set it by adding the ssh ClientAliveInterval parameter in /etc/ssh/sshd_config=30 --------[needed adjustment]"
fi

echo ''
echo 'ssh default port checking'
grep -i 'port' /etc/ssh/sshd_config
if [ $? == 30 ];then
    echo 'This port set the ssh'
else
    echo 'The port of SSH is not set. Set it by adding the ssh port parameter in /etc/ssh/sshd_config=8100 --------'[needed adjustment]''
fi

echo ''
grep -i 'X11Forwarding'  /etc/ssh/sshd_config
if [ $? == no ];then
    echo 'This X11Forwarding set the ssh'
else
    echo 'The X11Forwarding of SSH is not set. Set it by adding the ssh X11Forwarding parameter in /etc/ssh/sshd_config=no --------'[needed adjustment]''
fi



ehco 'SSH Allow SSH Environment Options'
grep -i "PermitUserEnvironment" /etc/ssh/sshd_config
if [ $? == no ];then
    echo "This ssh set the ssh Banner"
else
    echo 'The PermitUserEnvironment of SSH is not set  . Set it by adding the ssh PermitUserEnvironment parameter in /etc/ssh/sshd_config=no --------'[needed adjustment]''
fi

echo 'SSH Validated Ciphers'
grep -i "Ciphers" /etc/ssh/sshd_config
if [ $? == no ];then
    echo ">>>This Ciphers set the ssh Banner"
else
    echo "The Ciphers of SSH is not set  . Set it by adding the ssh Ciphers parameter in /etc/ssh/sshd_config=aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc --------[needed adjustment]"
fi

echo ''
grep -i "MACs" /etc/ssh/sshd_config
if [ $? == no ];then
    echo "This MACs set the ssh Banner"
else
    echo "The MACs of SSH is not set  . Set it by adding the ssh MACs parameter in /etc/ssh/sshd_config=hmac-sha2-512 --------[needed adjustment]"
fi

echo ''
echo 'Host-Based Authentication'
grep -i "Authentication" /etc/ssh/sshd_config
if [ $? == no ];then
    echo "This Authentication set the ssh Banner"
else
    echo "The Authentication of SSH is not set  . Set it by adding the ssh Authentication parameter in /etc/ssh/sshd_config=no --------[needed adjustment]"
fi

echo ''
echo 'SSH Server firewalld Firewall Exception'
firewall-cmd --list-all | grep ssh


#################################################################################
echo  "File Permissions and Masks checking"
#################################################################################
echo "Verify that System Executables Have Restrictive Permissions"
ls -al /bin /sbin /usr/bin /usr/libexec /usr/local/bin /usr/local/sbin /usr/sbin

echo " "
echo "Shared Library Files Have Root Ownership"
ls -al /lib /lib64 /usr/lib /usr/lib64

echo ""
echo "Shared Library Files Have Restrictive Permissions"
ls -al /lib
ls -al /lib64
ls -al /usr/lib
ls -al /usr/lib64

echo ''
echo "Owns group File"
ls -al /etc/group

echo ''
echo "Permissions on group File"
ls -al /etc/passwd

echo ''
echo "Permissions on shadow File"
ls -al /etc/shadow

echo ''
echo "User Who Owns gshadow File"
ls -al /etc/gshadow 

echo ''
echo "Group Who Owns group File"
ls -al /etc/group

echo ""
echo "Permissions on passwd File"
ls -al /etc/passwd

echo ""
echo "Group Who Owns passwd File"
ls -al /etc/passwd

echo ""
echo "Configure SELinux Policy"
getenforce

#################################################################################
echo "Restrict Root Logins"
#################################################################################
echo "Ensure that System Accounts Do Not Run a Shell Upon Login"
grep -i "nologin" /etc/passwd
if [ $? == nologin ];then
    echo "This Not Run a Shell Upon Login set"
else
    echo "The Not Run a Shell Upon Login is not set  . Set it by adding the ssh Authentication parameter in /etc/passwd=/bin/nologin --------[needed adjustment]"
fi

echo ''
echo "PASS_MIN_LEN"
grep -i "PASS_MIN_LEN" /etc/login.defs
if [ $? == 12 ];then
    echo 'This minimum length of the password set the 12'
else
    echo "The  minimum length of the password of SSH is not set  . Set it by adding the PASS_MIN_LEN parameter in /etc/login.defs=12  --------[needed adjustment]"
fi

echo ''
echo "Password Warning Age"
grep -i "PASS_WARN_AGE" /etc/login.defs
if [ $? == 7 ];then
    echo 'This Warning message before password expires set the 7'
else
    echo "The  Warning message before password expires  is not set  . Set it by adding the PASS_WARN_AGE parameter in /etc/login.defs=7  --------[needed adjustment]"
fi



echo "Password Minimum Age"
grep -i "PASS_MIN_DAYS"  /etc/login.defs
if [ $? == 1 ];then
    echo 'This After the password is changed, how long does it take to change the password again set the 1'
else
    echo "The  After the password is changed, how long does it take to change the password again is not set  . Set it by adding the PASS_MIN_DAYS parameter in /etc/login.defs=1  --------[needed adjustment]"
fi



#################################################################################
echo  "Set Lockouts for Failed Password Attempts"
#################################################################################
echo "Limit Password Reuse"
grep -i "remeber" /etc/pam.d/system-auth
if [ $? == 5 ];then
    echo 'This remeber password  set the 5'
else
    echo "The  remeber password is not set  . Set it by adding the remeber parameter in /pam.d/system-auth=5  --------[needed adjustment]"
fi

echo "Set Deny For Failed Password Attempts"
grep -i "lock" /etc/pam.d/system-auth
if [ $? == 5 ];then
    echo 'This Authentication Retry Prompts Permitted Per-Session  set the 5'
else
    echo "The  Authentication Retry Prompts Permitted Per-Session is not set  . Set it by adding the lock parameter in /pam.d/system-auth=5  --------[needed adjustment]"
fi

#################################################################################
echo  "Password Quality Requirements"
#################################################################################

echo " maximum number of digits that will generate a credit"
grep -i "dcredit" /etc/security/pwquality.conf
if [ $? == -1 ];then
    echo 'This pasword maximum number to be dcredit set the -1'
else
    echo "The  pasword maximum number of dcredit is not set  . Set it by adding the dcredit parameter in /etcsecurity/pwquality.conf=-1  --------[needed adjustment]"
fi

echo "  "
echo "The password must contain at least the minimum number"
grep -i "difok" /etc/security/pwquality.conf
if [ $? == 5 ];then
    echo 'The MThe password must contain at least the minimum number set the 5'
else
    echo "The The password must contain at least the minimum number is not set  . Set it by adding the difok parameter in /etcsecurity/pwquality.conf=5  --------[needed adjustment]"
fi

echo ""
echo "Password Special Characters"
grep -i "ocredit" /etc/security/pwquality.conf
if [ $? == 1 ];then
    echo 'This Password Special Characters set the 1'
else
    echo "The  Password Special Characters is not set  . Set it by adding the ocredit parameter in /etcsecurity/pwquality.conf=1  --------[needed adjustment]"
fi

echo ""
echo "minimum number of lower case letters"
grep  -i "lcredit" /etc/security/pwquality.conf
if [ $? == 1 ];then
    echo 'This  minimum number of lower case letters set the 1'
else
    echo "The  minimum number of lower case letters  is not set  . Set it by adding the lcredit parameter in /etcsecurity/pwquality.conf=1  --------[needed adjustment]"
fi

echo ""
echo "minimum number of upper case"
grep -i "ucredit" /etc/security/pwquality.conf
if [ $? == -1 ];then
    echo 'This  minimum number of upper case set the -1'
else
    echo "The  minimum number of upper case is not set  . Set it by adding the ucredit parameter in /etcsecurity/pwquality.conf=-1  --------[needed adjustment]"
fi


echo "Prevent Login to Accounts With Empty Password"
grep -i "nullok" /etc/pam.d/system-auth
if [ $? == nullok ];then
    echo 'This After the password is changed, how long does it take to change the password again set the 1'
else
    echo "The  After the password is changed, how long does it take to change the password again is not set  . Set it by adding the nullok parameter in /etc/login.defs=1  --------[needed adjustment]"
fi

echo "Set Password Hashing Algorithm"
grep -i "ENCRYPT_METHOD" /etc/login.defs
if [ $? == sha512 ];then
    echo 'This ENCRYPT_METHOD set the sha512'
else
    echo "The  ENCRYPT_METHOD is not set  . Set it by adding the ENCRYPT_METHOD parameter in /etc/login.defs=sha512  --------[needed adjustment]"
fi

echo " "
grep -i "crypt_style" /etc/libuser.conf
if [ $? == sha512 ];then
    echo 'This crypt_style set the sha512'
else
    echo "The  crypt_styleD is not set  . Set it by adding the crypt_style parameter in /etc/login.defs=sha512  --------[needed adjustment]"
fi

#################################################################################
echo "Verify firewall "
#################################################################################
echo ""
echo "Inspect and Activate Default firewalld Rules"
systemctl status firewalld.service

echo "firewall open port"
firewall-cmd --zone=public --list-ports | grep "tcp"
if [ ! -n "$1" ];then
    echo 'This firewall rules set '
else
    echo "The firewall rules  not set  . Set it by adding the crypt_style parameter in /etc/login.defs=firewall-cmd --zone=public --query-port=22/tcp  --------[needed adjustment]"
fi

echo ""
iptables --list  | grep "ACCEPT"
if [ ! -n "$1" ];then
    echo 'This firewall rules set '
else
    echo "The firewall rules  not set  . Set it by adding the crypt_style parameter in /etc/login.defs=firewall-cmd --zone=public --query-port=22/tcp  --------[needed adjustment]"
fi

echo ''
echo "UMASK 077"
grep -i "umask"  /etc/bashrc
if [ $? == 077 ];then
    echo 'This umask set '
else
    echo "The umask not set  . Set it by adding the 077 parameter in /etc/bashrc=077  --------[needed adjustment]"
fi

grep -i "umask"  /etc/csh.cshrc
grep -i "umask"  /etc/bashrc
if [ $? == 077 ];then
    echo 'This umask set '
else
    echo "The umask not set  . Set it by adding the 077 parameter in /etc/bashrc=077  --------[needed adjustment]"
fi

echo ""
echo "kernel checking"
sysctl -p

echo ""
echo "aide checking"
ps -ef | grep  "aide"
if [ $? == aide ];then
    echo 'This aide install '
else
    echo "The aide not install. Set it by yum install aide--------[needed adjustment]"
fi

echo "Checking complete"
###########################################################################################################################
Footer
