mode con: cols=120 lines=33
color a
@REM start_time 20230810
@REM Support System:Windows 11 And Windows 10 Professional
@REM athor:Mirai
@echo off

@echo off
Title  Windows 11 Professional Security Hardening Script
color a
echo=
echo "Back eregedister"
echo=
regedit/E C:\backup-eregedit.reg

rem Ensure 'Enforce password history' is set to '24 or more password(s)'
net accounts /uniquepw:24 
rem Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'
net accounts /maxpwage:365
rem Ensure 'Minimum password age' is set to '1 or more day(s)'
net accounts /minpwage:1 
rem Ensure 'Minimum password length' is set to '14 or more character(s)'
net accounts /minpwlen:14

rem Ensure 'Password must meet complexity requirements' is set to 'Enabled'
net accouts /uniquepw:yes
rem Ensure 'Relax minimum password length limits' is set to 'Enabled'.
rem Ensure 'Account lockout duration' is set to '15 or more minute(s)'
net accounts /lockoutthreshold:15
rem Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'

rem Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
net accounts /lockoutwindow:15

net accounts /forcelogoff:900   # Force log off {minutes:no}
net accounts /minpwage:1    # Minimum password age {days:0}
net accounts /maxpwage:365   # Max password age {days:unlimited}
net accounts /minpwlen:14    # Minimum password length {0-14, default 6}
net accounts /uniquepw:24   # Length of password history maintained {0-24}
net accounts /lockoutthreshold:15   # Lockout threshold
net accounts /lockoutwindow:15   # Lockout duration
secpol.msc
rem Ensure 'Accounts: Administrator account status' is set to 'Disabled'
net user administrator /active:no

rem Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'.
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Accounts: Guest account status' is set to 'Disabled'.
net user guest /active:no

rem Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Configure 'Accounts: Rename administrator account'
wmic useraccount where name='Administrator' rename 'epay'

rem Configure 'Accounts: Rename guest account'.
wmic useraccount where name='Guest' rename 'Invalid'

rem Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators and Interactive Users'.
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateDASD /t REG_DWORD /d 2 /f

rem Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

rem Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters " /v RequireSignOrSeal /t REG_DWORD /d 1 /f

rem Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f

rem Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f

rem Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" /v DisablePasswordChange /t REG_DWORD /d 0 /f

rem Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f
==========================

rem Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
reg add "KEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameter" /v RequireStrongKey /t REG_DWORD /d 1 /f

rem Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
reg add "KEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD  /t REG_DWORD /d 0 /f

rem Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System " /v DontDisplayLastUserName /t REG_DWORD /d 1 /f

rem Ensure 'Interactive logon: Machine account lockout threshold' is set to '10 or fewer invalid logon attempts, but not 0'
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v MaxDevicePasswordFailedAttempts /t REG_DWORD /d 30 /f

rem Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f

rem Configure 'Interactive logon: Message text for users attempting to log on'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Configure 'Interactive logon: Message title for users attempting to log on'.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" /v legalnoticetext /t REG_SZ /d 勿不要打开未知附件或下载软件，使用强密码并定期备份数据. /f

rem Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_DWORD /d 4 /f

rem Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v PasswordExpiryWarning /t REG_DWORD /d 14 /f

rem Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScRemoveOption /t REG_DWORD /d 0x2 /f

rem Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f

rem Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f

rem Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f

rem Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" /v AutoDisconnect /t REG_DWORD /d 15 /f

rem Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f

rem Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
reg add "KEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f

rem Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" /v EnableForcedLogOff /t REG_DWORD /d 1 /f

rem Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher
reg add "EY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v SMBServerNameHardeningLevel /t REG_DWORD /d 1 /f

rem Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
powershell.exe 
$secpol = secedit /export /cfg $env:temp\secexport.cfg
$secpolContent = Get-Content $env:temp\secexport.cfg
$allowAnonymous = $secpolContent | Select-String "LSAAnonymousNameLookup"
$settingValue = $allowAnonymous.ToString().Split("=")[1].Trim()

if ($settingValue -eq '0') {
    Write-Host "Allow anonymous SID/Name translation is set to 'Disabled'"
} elseif ($settingValue -eq '1') {
    Write-Host "Allow anonymous SID/Name translation is set to 'Enabled'"
} else {
    Write-Host "Unable to determine the status of 'Allow anonymous SID/Name translation'"
}

cmd.exe
::
rem Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'
reg add "Y_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v NRestrictAnonymousSAM /t REG_DWORD /d 1 /f

rem Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
reg add "KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f

rem Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableDomainCreds /t REG_DWORD /d 1 /f

rem Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /0 /f

rem Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to 'None'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d 3 /f

rem Ensure 'Network access: Remotely accessible registry paths' is configured
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /d "System\CurrentControlSet\Control\ProductOptions\0System\CurrentControlSet\Control\Server Applications\0Software\Microsoft\Windows NT\CurrentVersion" /f

rem Ensure 'Network access: Remotely accessible registry paths and sub-paths' is configured
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /d "System\CurrentControlSet\Control\Print\Printers\0System\CurrentControlSet\Services\Eventlog\0Software\Microsoft\OLAP Server\0Software\Microsoft\Windows NT\CurrentVersion\Print\0Software\Microsoft\Windows NT\CurrentVersion\Windows\0System\CurrentControlSet\Control\ContentIndex\0System\CurrentControlSet\Control\Terminal Server\0System\CurrentControlSet\Control\Terminal Server\UserConfig\0System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration\0Software\Microsoft\Windows NT\CurrentVersion\Perflib\0System\CurrentControlSet\Services\SysmonLog" /f

rem Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f

rem Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictremotesam /t REG_DWORD /d 3 /f
rem Set 'Administrators: Remote Access: Allow'
NET LOCALGROUP "Remote Desktop Users" "Administrators" /add
NET LOCALGROUP "Remote Desktop Users" "Domain Admins" /add
gpupdate /force

rem Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
reg add "KEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d "" /f

rem Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v ForceGuest /t REG_DWORD /d 0 /f

rem Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 1 /f

rem Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f

rem Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u" /v AllowOnlineID /t REG_DWORD /0 /f

rem Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 0x7ffffff8 /f

rem Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 0x7ffffff8 /f

rem Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v EnableForcedLogOff  /t REG_DWORD /d 1 /f

rem Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f

rem Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher.
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 1 /f

rem Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f

rem Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'.
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f

rem Ensure 'System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User is prompted when the key is first used' or higher
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography" /v ForceKeyProtection /t REG_DWORD /d 2 /f

rem Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel" /v ObCaseInsensitive /t REG_DWORD /d 1 /f

rem Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f

rem Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f

rem Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f

rem Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f

rem Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f

rem Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f

rem Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f

rem Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f

rem Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f

rem Ensure 'Bluetooth Audio Gateway Service (BTAGService)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Bluetooth Support Service (bthserv)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Geolocation Service (lfsvc)' is set to 'Disabled'.
reg add "KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or 'Not Installed'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IISADMIN" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Infrared monitor service (irmon)' is set to 'Disabled' or 'Not Installed'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\irmon" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Internet Connection Sharing (ICS) (SharedAccess)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdsvc" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'LxssManager (LxssManager)' is set to 'Disabled' or 'Not Installed'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxssManager" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Disabled' or 'Not Installed'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FTPSVC" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'OpenSSH SSH Server (sshd)' is set to 'Disabled' or 'Not Installed'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sshd" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Peer Name Resolution Protocol (PNRPsvc)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPsvc" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Peer Networking Grouping (p2psvc)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2psvc" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Peer Networking Identity Manager (p2pimsvc)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2pimsvc" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'PNRP Machine Name Publication Service (PNRPAutoReg)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPAutoReg" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Print Spooler (Spooler)' is set to 'Disabled'.
reg add "HKEYEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Problem Reports and Solutions Control Panel Support (wercplsupport)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wercplsupport" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Remote Access Auto Connection Manager (RasAuto)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Remote Desktop Configuration (SessionEnv)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SessionEn" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Remote Desktop Services UserMode Port Redirector (UmRdpService)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcLocator" /v Start /t REG_DWORD /d 4 /f

::rem   Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled'.
::reg add "HKKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteRegistry" tart /t REG_DWORD /d 4 /f

rem Ensure 'Routing and Remote Access (RemoteAccess)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Server (LanmanServer)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Simple TCP/IP Services (simptcp)' is set to 'Disabled' or 'Not Installed'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\simptcp" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'SNMP Service (SNMP)' is set to 'Disabled' or 'Not Installed'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Special Administration Console Helper (sacsvr)' is set to 'Disabled' or 'Not Installed'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sacsvr" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SSDPSRV" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled'.
reg add "EY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upnphost" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Web Management Service (WMSvc)' is set to 'Disabled' or 'Not Installed'.
reg add "KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMSvc" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Windows Error Reporting Service (WerSvc)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Windows Event Collector (Wecsvc)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wecsvc" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Windows Media Player Network Sharing Service (WMPNetworkSvc)' is set to 'Disabled' or 'Not Installed'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Windows Mobile Hotspot Service (icssvc)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\icssvc" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Windows Push Notifications System Service (WpnService)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnService" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Windows PushToInstall Service (PushToInstall)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PushToInstall" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Windows Remote Management (WS-Management) (WinRM)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'World Wide Web Publishing Service (W3SVC)' is set to 'Disabled' or 'Not Installed'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Xbox Accessory Management Service (XboxGipSvc)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc"  /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Xbox Live Auth Manager (XblAuthManager)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Xbox Live Game Save (XblGameSave)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblGameSave" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Xbox Live Networking Service (XboxNetApiSvc)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v EnableFirewall /t REG_DWORD /d 1 /f

rem Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v DefaultInboundAction /t REG_DWORD /d 1 /f

rem Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v DefaultOutboundAction /t REG_DWORD /d 0 /f

rem Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v DisableNotifications /t REG_DWORD /d 1 /f

rem Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'.
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v logFilePath /t REG_EXPAND_SZ /d "%SystemRoot%\System32\logfiles\firewall\domainfw.log" /f

rem Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v LogFileSize /t REG_DWORD /d 16384 /f

rem Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v LogDroppedPackets /t REG_DWORD /d 1 /f

rem Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v LogSuccessfulConnections /t REG_DWORD /d 1 /f

rem Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile " /v EnableFirewall /t REG_DWORD /d 1 /f

rem Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'.
reg add ":HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v DefaultInboundAction /t REG_DWORD /d 1 /f

rem Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v DefaultOutboundAction /t REG_DWORD /d 0 /f

rem Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v DisableNotifications /t REG_DWORD /d 1 /f

rem Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" /v logFilePath /t REG_EXPAND_SZ /d "System32\\logfiles\\firewall\\privatefw.log" /f

rem Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" /v LogFileSize /t REG_DWORD /d 16284 /f

rem Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" /v LogDroppedPackets /t REG_DWORD /d 1 /f

rem Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" /v LogSuccessfulConnections /t REG_DWORD /d 1 /f

rem Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v EnableFirewall /t REG_DWORD /d 1 /f

rem Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v DefaultInboundAction /t REG_DWORD /d 1 /f

rem Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v DefaultOutboundAction /t REG_DWORD /d 0 /f

rem Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v DisableNotifications /t REG_DWORD /d 1 /f

rem Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v AllowLocalPolicyMerge /t REG_DWORD /d 0 /f

rem Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v AllowLocalIPsecPolicyMerge /t REG_DWORD /d 0 /f

rem Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v logFilePath /t REG_EXPAND_SZ /d "System32\\logfiles\\firewall\\publicfw.log" /f

rem Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v LogFileSize /t REG_DWORD /d 16284 /f

rem Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v LogDroppedPackets /t REG_DWORD /d 1 /f

rem Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" /v LogSuccessfulConnections /t REG_DWORD /d 1 /f
::

rem Ensure 'Audit Credential Validation' is set to 'Success and Failure'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Application Group Management' is set to 'Success and Failure'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Security Group Management' is set to include 'Success'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit User Account Management' is set to 'Success and Failure'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit PNP Activity' is set to include 'Success'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Process Creation' is set to include 'Success'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Account Lockout' is set to include 'Failure'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Group Membership' is set to include 'Success'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Logoff' is set to include 'Success'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Logon' is set to 'Success and Failure'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Special Logon' is set to include 'Success'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Detailed File Share' is set to include 'Failure'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit File Share' is set to 'Success and Failure'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Removable Storage' is set to 'Success and Failure'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Audit Policy Change' is set to include 'Success'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Authentication Policy Change' is set to include 'Success'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Authorization Policy Change' is set to include 'Success'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Other Policy Change Events' is set to include 'Failure'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

:: System Set to 'Success and Failure'
rem Ensure 'Audit IPsec Driver' is set to 'Success and Failure'.
auditpol /set /category:{69979848-797A-11D9-BED3-505054503030} /subcategory:{0CCE9213-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

rem Ensure 'Audit Other System Events' is set to 'Success and Failure'.
auditpol /set /category:{69979848-797A-11D9-BED3-505054503030} /subcategory:{0CCE9214-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
::
rem Ensure 'Audit Security State Change' is set to include 'Success'.
auditpol /set /category:{69979848-797A-11D9-BED3-505054503030} /subcategory:{0CCE9210-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
::
rem Ensure 'Audit Security System Extension' is set to include 'Success'.
auditpol /set /category:{69979848-797A-11D9-BED3-505054503030} /subcategory:{0CCE9211-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
::
rem Ensure 'Audit System Integrity' is set to 'Success and Failure'.
auditpol /set /category:{69979848-797A-11D9-BED3-505054503030} /subcategory:{0CCE9212-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
::
rem Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f

rem Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenSlideshow /t REG_DWORD /d 1 /f

rem Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization" /v AllowInputPersonalization /t REG_DWORD /d 0 /f

rem Ensure 'Allow Online Tips' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v AllowOnlineTips /t REG_DWORD /d 0 /f

rem Ensure LAPS AdmPwd GPO Extension / CSE is installed.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd" /v PwdExpirationProtectionEnabledr /t REG_DWORD /d 1 /f

rem Ensure 'Enable Local Admin Password Management' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled /t REG_DWORD /d 1 /f

rem Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters'.
reg add "KEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd" /v PasswordComplexity /t REG_DWORD /d 4 /f

rem Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd" /v PasswordLength /t REG_DWORD /d 15 /f

rem Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd" /v PasswordAgeDays /t REG_DWORD /d 30 /f

rem Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f

rem Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Configure SMB v1 server' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f

rem Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DisableExceptionChainValidation /t REG_DWORD /d 0 /f

rem Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f

rem Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v NodeType /t REG_DWORD /d 2 /f

rem Ensure 'WDigest Authentication' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v NUseLogonCredential /t REG_DWORD /d 0 /f

rem Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f

rem Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f

rem Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f

rem Ensure 'MSS: (DisableSavePassword) Prevent the dial-up password from being saved' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" /v DisableSavePassword /t REG_DWORD /d 1 /f

rem Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f

rem Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v KeepAliveTime /t REG_DWORD /d 300000 /f

rem Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f

rem Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v PerformRouterDiscovery /t REG_DWORD /d 0 /f

rem Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode /t REG_DWORD /d 1 /f

rem Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScreenSaverGracePeriod /t REG_DWORD /d 5 /f

rem Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" /v NTcpMaxDataRetransmissions /t REG_DWORD /d 3 /f

rem Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxDataRetransmissions /t REG_DWORD /d 3 /f

rem Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security" /v WarningLevel /t REG_DWORD /d 90 /f

rem Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient " /v DoHPolicy /t REG_DWORD /d 2 /f

rem Ensure 'Turn off multicast name resolution' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v  EnableMulticast /t REG_DWORD /d 0 /f

rem Ensure 'Enable Font Providers' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableFontProviders /t REG_DWORD /d 0 /f

rem Ensure 'Enable insecure guest logons' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 3 /f

rem Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v EnableLLTDIO /t REG_DWORD /d 0 /f

rem Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v EnableRspndr /t REG_DWORD /d 3 /f

rem Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Peernet" /v Disabled /t REG_DWORD /d 3 /f

rem Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_AllowNetBridge_NLA /t REG_DWORD /d 0 /f

rem Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_ShowSharedAccessUI /t REG_DWORD /d 0 /f

rem Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_StdDomainUserSetLocation /t REG_DWORD /d 1 /f

rem Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /v \\*\NETLOGON /t REG_SZ /d "RequireMutualAuthentication=1,RequireIntegrity=1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /v \\*\SYSVOL /t REG_SZ /d "RequireMutualAuthentication=1,RequireIntegrity=1" /f

rem Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)').
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" /v DisabledComponents /t REG_DWORD /d 255 /f

rem Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v DisableFlashConfigRegistrar /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v DisableInBand802DOT11Registrar /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v DisableUPnPRegistrar /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v DisableWPDRegistrar /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v EnableRegistrars /t REG_DWORD /d 0 /f

rem Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" /v DisableWcnUi /t REG_DWORD /d 1 /f

rem Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fMinimizeConnections /t REG_DWORD /d 3 /f

rem Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fBlockNonDomain /t REG_DWORD /d 1 /f

rem Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f

rem Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsNT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f

rem Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'.
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsNT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /t REG_DWORD /d 0 /f

rem Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'.
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsNT\Printers\PointAndPrint" /v UpdatePromptSettings /t REG_DWORD /d 0 /f

rem Ensure 'Turn off notifications network usage' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoCloudApplicationNotification /t REG_DWORD /d 1 /f

rem Ensure 'Include command line in process creation events' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

rem Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 1 /f

rem Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f

rem Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f

rem Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 3 /f

rem Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v HypervisorEnforcedCodeIntegrity /t REG_DWORD /d 1 /f

rem Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v HVCIMATRequired /t REG_DWORD /d 1 /f

rem Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v ConfigureSystemGuardLaunch /t REG_DWORD /d 1 /f

rem Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f

rem Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f

rem Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v NoBackgroundPolicy /t REG_DWORD /d 0 /f

rem Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v NoGPOListChanges /t REG_DWORD /d 0 /f

rem Ensure 'Continue experiences on this device' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableCdp /t REG_DWORD /d 0 /f

rem Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableBkGndGroupPolicy /t REG_DWORD /d  /f

rem Ensure 'Turn off access to the Store' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoUseStoreOpenWith /t REG_DWORD /d 1 /f

rem Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f

rem Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v PreventHandwritingDataSharing /t REG_DWORD /d 1 /f

rem Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v PreventHandwritingErrorReports /t REG_DWORD /d 1 /f

rem Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" /v ExitOnMSICW /t REG_DWORD /d 1 /f

rem Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWebServices /t REG_DWORD /d 1 /f

rem Ensure 'Turn off printing over HTTP' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f

rem Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" /v NoRegistration /t REG_DWORD /d 1 /f

rem Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion" /v DisableContentFileUpdates /t REG_DWORD /d 1 /f

rem Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoOnlinePrintsWizard /t REG_DWORD /d 1 /f

rem Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoPublishingWizard /t REG_DWORD /d 1 /f

rem Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client" /v CEIP /t REG_DWORD /d 2 /f

rem Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f

rem Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 0 /f

rem Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" /v DeviceEnumerationPolicy /t REG_DWORD /d 0 /f

rem Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Control Panel\International" /v BlockUserInputMethodsForSignIn /t REG_DWORD /d 1 /f

rem Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v BlockUserFromShowingAccountDetailsOnSignin /t REG_DWORD /d 1 /f

rem Ensure 'Do not display network selection UI' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f

rem Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v DontEnumerateConnectedUsers /t REG_DWORD /d 1 /f

rem Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnumerateLocalUsers /t REG_DWORD /d 0 /f

rem Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v DisableLockScreenAppNotifications /t REG_DWORD /d 1 /f

rem Ensure 'Turn off picture password sign-in' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v BlockDomainPicturePassword /t REG_DWORD /d 1 /f

rem Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowDomainPINLogon /t REG_DWORD /d 0 /f

rem Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowCrossDeviceClipboard /t REG_DWORD /d 0 /f

rem Ensure 'Allow upload of User Activities' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f

rem Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" /v DCSettingIndex /t REG_DWORD /d 0 /f

rem Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" /v ACSettingIndex /t REG_DWORD /d 0 /f

rem Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /t REG_DWORD /d 1 /f

rem Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /t REG_DWORD /d 1 /f

rem Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowUnsolicited /t REG_DWORD /d 0 /f

rem Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp /t REG_DWORD /d 0 /f

rem Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v EnableAuthEpResolution /t REG_DWORD /d 1 /f

rem Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_DWORD /d 1 /f

rem Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v DisableQueryRemoteServer /t REG_DWORD /d 0 /f

rem Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v ScenarioExecutionEnabled /t REG_DWORD /d 0 /f

rem Ensure 'Turn off the advertising ID' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f

rem Ensure 'Enable Windows NTP Client' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" /v Enabled /t REG_DWORD /d 1 /f

rem Ensure 'Enable Windows NTP Server' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" /v Enabled /t REG_DWORD /d 0 /f

rem Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" /v AllowSharedLocalAppData /t REG_DWORD /d 0 /f

rem Ensure 'Prevent non-admin users from installing packaged Windows apps' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Appx" /v BlockNonAdminUserInstall /t REG_DWORD /d 1 /f

rem Ensure 'Let Windows apps activate with voice while the system is locked' is set to 'Enabled: Force Deny'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f

rem Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v MSAOptional /t REG_DWORD /d 1 /f

rem Ensure 'Block launching Universal Windows apps with Windows Runtime API access from hosted content.' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v BlockHostedAppAccessWinRT /t REG_DWORD /d 1 /f

rem Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f

rem Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f

rem Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'.
reg add "KEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f

rem Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f

rem Ensure 'Allow Use of Camera' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Camera" /v AllowCamera /t REG_DWORD /d 0 /f

rem Ensure 'Turn off cloud consumer account state content' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableConsumerAccountStateContent /t REG_DWORD /d 1 /f

rem Ensure 'Turn off cloud optimized content' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableCloudOptimizedContent /t REG_DWORD /d 1 /f

rem Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f

rem Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Connect" /v RequirePinForPairing /t REG_DWORD /d 2 /f

rem Ensure 'Do not display the password reveal button' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v DisablePasswordReveal /t REG_DWORD /d 1 /f

rem Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" /v EnumerateAdministrators /t REG_DWORD /d 0 /f

rem Ensure 'Prevent the use of security questions for local accounts' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v NoLocalPasswordResetQuestions /t REG_DWORD /d 1 /f

rem Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 1 /f

rem Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DisableEnterpriseAuthProxy /t REG_DWORD /d 1 /f

rem Ensure 'Disable OneSettings Downloads' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DisableOneSettingsDownloads /t REG_DWORD /d 1 /f

rem Ensure 'Do not show feedback notifications' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f

rem Ensure 'Enable OneSettings Auditing' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v EnableOneSettingsAuditing /t REG_DWORD /d 1 /f

rem Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitDiagnosticLogCollection /t REG_DWORD /d 1 /f

rem Ensure 'Limit Dump Collection' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitDumpCollection /t REG_DWORD /d 1 /f

rem Ensure 'Toggle user control over Insider builds' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v AllowBuildPreview /t REG_DWORD /d 0 /f

rem Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" /v Retention /t REG_DWORD /d 0 /f

rem Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" /v MaxSize /t REG_DWORD /d 32768 /f

rem Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" /v Retention /t REG_DWORD /d 0 /f

rem Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" /v MaxSize /t REG_DWORD /d 196608 /f

rem Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" /v Retention /t REG_DWORD /d 0 /f

rem Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" /v MaxSize /t REG_DWORD /d 32768 /f

rem Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" /v Retention /t REG_DWORD /d 0 /f

rem Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\" /v MaxSize /t REG_DWORD /d 32768 /f

rem Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f

rem Ensure 'Turn off heap termination on corruption' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f

rem Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f

rem Ensure 'Prevent the computer from joining a homegroup' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" /v DisableHomeGroup /t REG_DWORD /d 1 /f

rem Ensure 'Turn off location' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f

rem Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v AllowMessageSync /t REG_DWORD /d 0 /f

rem Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftAccount" /v DisableUserAuth /t REG_DWORD /d 1 /f

rem Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v LocalSettingOverrideSpynetReporting /t REG_DWORD /d 0 /f

rem Ensure 'Join Microsoft MAPS' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpynetReporting /t REG_DWORD /d 0 /f

rem Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" /v ExploitGuard_ASR_Rules /t REG_DWORD /d 1 /f

rem Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured.
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 26190899-1602-49E8-8B27-eB1D0A1CE869 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 3B576869-A4EC-4529-8536-B80A7769E899 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 9E6C4E1F-7D60-472F-bA1A-A39EF669E4B2 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v D3E037E1-3EB8-44C8-A917-57927947596D /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v D4F940AB-401B-4EFC-AADC-AD5F3C50688A /t REG_DWORD /d 1 /f

rem Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v EnableNetworkProtection/t REG_DWORD /d 1 /f

rem Ensure 'Enable file hash computation feature' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v EnableFileHashComputation /t REG_DWORD /d 1 /f

rem Ensure 'Scan all downloaded files and attachments' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-TimeProtection" /v DisableIOAVProtection /t REG_DWORD /d 0 /f

rem Ensure 'Turn off real-time protection' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-TimeProtection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f

rem Ensure 'Turn on behavior monitoring' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-TimeProtection" /v DisableBehaviorMonitoring/t REG_DWORD /d 0 /f

rem Ensure 'Turn on script scanning' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-TimeProtection" /v DisableScriptScanning /t REG_DWORD /d 0 /f

rem Ensure 'Configure Watson events' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v DisableGenericRePorts /t REG_DWORD /d 1 /f

rem Ensure 'Scan removable drives' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v DisableRemovableDriveScanning /t REG_DWORD /d 0 /f

rem Ensure 'Turn on e-mail scanning' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v PUAProtection /t REG_DWORD /d 1 /f

rem Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'.
reg add "" /v NoConnectedUser /t REG_DWORD /d 3 /f

rem Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f

rem Ensure 'Enable news and interests on the taskbar' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f

rem Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f

rem Ensure 'Turn off Push To Install service' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /t REG_DWORD /d 1 /f

rem Ensure 'Do not allow passwords to be saved' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v DisablePasswordSaving /t REG_DWORD /d 1 /f

rem Ensure 'Allow users to connect remotely by using Remote Desktop Services' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDenyTSConnections /t REG_DWORD /d 1 /f

rem Ensure 'Allow UI Automation redirection' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v EnableUiaRedirection /t REG_DWORD /d 0 /f

rem Ensure 'Do not allow COM port redirection' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCcm /t REG_DWORD /d 1 /f

rem Ensure 'Do not allow drive redirection' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f

rem Ensure 'Do not allow location redirection' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableLocationRedir /t REG_DWORD /d 1 /f

rem Ensure 'Do not allow LPT port redirection' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableLPT /t REG_DWORD /d 1 /f

rem Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisablePNPRedir /t REG_DWORD /d 1 /f

rem Ensure 'Always prompt for password upon connection' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fPromptForPassword /t REG_DWORD /d 1 /f

rem Ensure 'Require secure RPC communication' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f

rem Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v SecurityLayer/t REG_DWORD /d 2 /f

rem Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v UserAuthentication /t REG_DWORD /d 1 /f

rem Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MinEncryptionLevel /t REG_DWORD /d 3 /f

rem Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less, but not Never (0)'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MaxIdleTime /t REG_DWORD /d 900000 /f

rem Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MaxDisconnectionTime /t REG_DWORD /d 60000 /f

rem Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v DeleteTempDirsOnExit /t REG_DWORD /d 1 /f

rem Ensure 'Prevent downloading of enclosures' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" /v DisableEnclosureDownload /t REG_DWORD /d 1 /f

rem Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCloudSearch /t REG_DWORD /d 0 /f

rem Ensure 'Allow Cortana' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f

rem Ensure 'Allow Cortana above lock screen' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaAboveLock /t REG_DWORD /d 0 /f

rem Ensure 'Allow indexing of encrypted files' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f

rem Ensure 'Allow search and Cortana to use location' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f

rem Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f

rem Ensure 'Disable all apps from Microsoft Store' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f

rem Ensure 'Only display the private store within the Microsoft Store' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v RequirePrivateStoreOnly /t REG_DWORD /d 1 /f

rem Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v AutoDownload /t REG_DWORD /d 4 /f

rem Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v DisableOSUpgrade /t REG_DWORD /d 1 /f

rem Ensure 'Turn off the Store application' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f

rem Ensure 'Allow widgets' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f

rem Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Block /f
rem Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f

rem Ensure 'Prevent bypassing Windows Defender SmartScreen prompts for sites' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v PreventOverride/t REG_DWORD /d 1 /f

rem Ensure 'Enables or disables Windows Game Recording and Broadcasting' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR " /v AllowGameDVR/t REG_DWORD /d 0 /f

rem Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f

rem Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v AllowWindowsInkWorkspace /t REG_DWORD /d 3 /f

rem Ensure 'Allow user control over installs' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" /v EnableUserControl /t REG_DWORD /d 0 /f

rem Ensure 'Always install with elevated privileges' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f

rem Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f

rem Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableAutomaticRestartSignOn /t REG_DWORD /d 1 /f

rem Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

rem Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 0 /f

rem Ensure 'Allow Basic authentication' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowBasic /t REG_DWORD /d 0 /f

rem Ensure 'Allow unencrypted traffic' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v  AllowUnencryptedTraffic /t REG_DWORD /d 0 /f

rem Ensure 'Disallow Digest authentication' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowDigest  /t REG_DWORD /d 0 /f

rem Ensure 'Allow Basic authentication' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Servic" /v AllowBasic  /t REG_DWORD /d 0 /f

rem Ensure 'Allow remote server management through WinRM' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowAutoConfig /t REG_DWORD /d 0 /f

rem Ensure 'Allow unencrypted traffic' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencryptedTraffic  /t REG_DWORD /d 0 /f

rem Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
reg add "KEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v DisableRunAs /t REG_DWORD /d 1 /f

rem Ensure 'Allow Remote Shell Access' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v AllowRemoteShellAccess /t REG_DWORD /d 1 /f

rem Ensure 'Allow clipboard sharing with Windows Sandbox' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Sandbox" /v AllowClipboardRedirection /t REG_DWORD /d 0 /f

rem Ensure 'Allow networking in Windows Sandbox' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Sandbox" /v AllowNetworking  /t REG_DWORD /d 0 /f

rem Ensure 'Prevent users from modifying settings' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" /v DisallowExploitProtectionOverride /t REG_DWORD /d 1 /f

rem Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 0 /f

rem Ensure 'Configure Automatic Updates' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f

rem Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f

rem Ensure 'Remove access to "Pause updates" feature' is set to 'Enabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v SetDisablePauseUXAccess /t REG_DWORD /d 1 /f

rem Ensure 'Manage preview builds' is set to 'Disabled'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v ManagePreviewBuildsPolicyValue /t REG_DWORD /d 1 /f

rem Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days'.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DeferFeatureUpdatesPeriodInDays /t REG_DWORD /d 180 /f
