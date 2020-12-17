SSH Linux command: ssh <username>@<address> –p <port>
ssh bandit20@bandit.labs.overthewire.org -p 2220

The username is always the level name
The password is the previous level flag

username: bandit0
password: bandit0

## Level 0 → 1
```shell
ls: "readme" file
cat readme: boJ9jbbUNNfktd78OOpsqOltutMc3MY1
```
## Level 1 → 2
```shell
ls: "-" file
cat ./- : CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
```
## Level 2 → 3
```shell
ls : "spaces in this filename" file
cat ./spaces\ in\ this\ filename : UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
```
## Level 3 → 4
```shell
bandit3@bandit:~$ ls
inhere
bandit3@bandit:~$ cd inhere/
bandit3@bandit:~/inhere$ ls -al
total 12
drwxr-xr-x 2 root    root    4096 May  7  2020 .
drwxr-xr-x 3 root    root    4096 May  7  2020 ..
-rw-r----- 1 bandit4 bandit3   33 May  7  2020 .hidden
bandit3@bandit:~/inhere$ cat .hidden
pIwrPrtPN36QITSp3EQaw936yaFoFgAB
```
## Level 4 → 5
```shell
bandit4@bandit:~$ ls
inhere
bandit4@bandit:~$ cd inhere/
bandit4@bandit:~/inhere$ file -- *
-file00: data
-file01: data
-file02: data
-file03: data
-file04: data
-file05: data
-file06: data
-file07: ASCII text
-file08: data
-file09: data
bandit4@bandit:~/inhere$ cat ./-file07
koReBOKuIDDepwhWk7jZC0RTdopnAYKh
```
## Level 5 → 6
```shell
bandit5@bandit:~$ ls
inhere
bandit5@bandit:~$ cd inhere/
bandit5@bandit:~/inhere$ ls
maybehere00  maybehere03  maybehere06  maybehere09  maybehere12  maybehere15  maybehere18
maybehere01  maybehere04  maybehere07  maybehere10  maybehere13  maybehere16  maybehere19
maybehere02  maybehere05  maybehere08  maybehere11  maybehere14  maybehere17
bandit5@bandit:~/inhere$ cd maybehere00
bandit5@bandit:~/inhere/maybehere00$ ls
-file1  -file2  -file3  spaces file1  spaces file2  spaces file3
bandit5@bandit:~/inhere/maybehere00$ cd ..
bandit5@bandit:~/inhere$ cd ..
bandit5@bandit:~$ find inhere -size 1033c
inhere/maybehere07/.file2
bandit5@bandit:~$ cd inhere/maybehere07/
bandit5@bandit:~/inhere/maybehere07$ cat ./.file2
DXjZPULLxYr17uwoI01bNLQbtFemEgo7
```
## Level 6 → 7
```shell
bandit6@bandit:~$ cd /
bandit6@bandit:/$ find . -size 33c -group bandit6 -user bandit7 | grep bandit7
find: ‘./root’: Permission denied
find: ‘./home/bandit28-git’: Permission denied
find: ‘./home/bandit30-git’: Permission denied
find: ‘./home/bandit5/inhere’: Permission denied
find: ‘./home/bandit27-git’: Permission denied
find: ‘./home/bandit29-git’: Permission denied
find: ‘./home/bandit31-git’: Permission denied
find: ‘./lost+found’: Permission denied
find: ‘./etc/ssl/private’: Permission denied
find: ‘./etc/polkit-1/localauthority’: Permission denied
find: ‘./etc/lvm/archive’: Permission denied
find: ‘./etc/lvm/backup’: Permission denied
find: ‘./sys/fs/pstore’: Permission denied
find: ‘./proc/tty/driver’: Permission denied
find: ‘./proc/1153/task/1153/fd/6’: No such file or directory
find: ‘./proc/1153/task/1153/fdinfo/6’: No such file or directory
find: ‘./proc/1153/fd/5’: No such file or directory
find: ‘./proc/1153/fdinfo/5’: No such file or directory
find: ‘./cgroup2/csessions’: Permission denied
find: ‘./boot/lost+found’: Permission denied
find: ‘./tmp’: Permission denied
find: ‘./run/lvm’: Permission denied
find: ‘./run/screen/S-bandit0’: Permission denied
find: ‘./run/screen/S-bandit12’: Permission denied
find: ‘./run/screen/S-bandit11’: Permission denied
find: ‘./run/screen/S-bandit30’: Permission denied
find: ‘./run/screen/S-bandit16’: Permission denied
find: ‘./run/screen/S-bandit4’: Permission denied
find: ‘./run/screen/S-bandit3’: Permission denied
find: ‘./run/screen/S-bandit28’: Permission denied
find: ‘./run/screen/S-bandit33’: Permission denied
find: ‘./run/screen/S-bandit17’: Permission denied
find: ‘./run/screen/S-bandit10’: Permission denied
find: ‘./run/screen/S-bandit9’: Permission denied
find: ‘./run/screen/S-bandit15’: Permission denied
find: ‘./run/screen/S-bandit20’: Permission denied
find: ‘./run/screen/S-bandit7’: Permission denied
find: ‘./run/screen/S-bandit2’: Permission denied
find: ‘./run/screen/S-bandit1’: Permission denied
find: ‘./run/screen/S-bandit29’: Permission denied
find: ‘./run/screen/S-bandit26’: Permission denied
find: ‘./run/screen/S-bandit18’: Permission denied
find: ‘./run/screen/S-bandit13’: Permission denied
find: ‘./run/screen/S-bandit31’: Permission denied
find: ‘./run/screen/S-bandit8’: Permission denied
find: ‘./run/screen/S-bandit14’: Permission denied
find: ‘./run/screen/S-bandit19’: Permission denied
find: ‘./run/screen/S-bandit21’: Permission denied
find: ‘./run/screen/S-bandit22’: Permission denied
find: ‘./run/screen/S-bandit24’: Permission denied
find: ‘./run/screen/S-bandit25’: Permission denied
find: ‘./run/shm’: Permission denied
find: ‘./run/lock/lvm’: Permission denied
find: ‘./var/spool/bandit24’: Permission denied
find: ‘./var/spool/cron/crontabs’: Permission denied
find: ‘./var/spool/rsyslog’: Permission denied
find: ‘./var/tmp’: Permission denied
find: ‘./var/lib/apt/lists/partial’: Permission denied
find: ‘./var/lib/polkit-1’: Permission denied
./var/lib/dpkg/info/bandit7.password
find: ‘./var/log’: Permission denied
find: ‘./var/cache/apt/archives/partial’: Permission denied
find: ‘./var/cache/ldconfig’: Permission denied
bandit6@bandit:/$ cat ./var/lib/dpkg/info/bandit7.password
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
```
## Level 7 → 8
```shell
bandit7@bandit:~$ ls
data.txt
bandit7@bandit:~$ strings data.txt | grep millionth
millionth       cvX2JJa4CFALtqS87jk27qwqGhBM9plV
```
## Level 8 → 9
```shell
bandit8@bandit:~$ sort data.txt | uniq -u
UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
```
## Level 9 → 10
```shell
bandit9@bandit:~$ strings data.txt | grep ===
========== the*2i"4
========== password
Z)========== is
&========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
```
## Level 10 → 11
```shell
bandit10@bandit:~$ ls
data.txt
bandit10@bandit:~$ base64 -d data.txt
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
```
## Level 11 → 12
```shell
bandit11@bandit:~$ cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
```
## Level 12 → 13
```shell
bandit12@bandit:~$ mkdir /tmp/griggo
bandit12@bandit:~$ cp data.txt /tmp/griggo
bandit12@bandit:~$ cd /
bandit12@bandit:/$ cd tmp/griggo
bandit12@bandit:/tmp/griggo$ xxd -r data.txt > rev.gz
bandit12@bandit:/tmp/griggo$ gzip -d rev.gz
bandit12@bandit:/tmp/griggo$ ls
data.txt  rev
bandit12@bandit:/tmp/griggo$ mv rev rev.bz2
bandit12@bandit:/tmp/griggo$ bzip2 -d rev.bz2
bandit12@bandit:/tmp/griggo$ ls
data.txt  rev
bandit12@bandit:/tmp/griggo$ file rev
rev: gzip compressed data, was "data4.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
bandit12@bandit:/tmp/griggo$ mv rev rev.gz
bandit12@bandit:/tmp/griggo$ gzip -d rev.gz
bandit12@bandit:/tmp/griggo$ ls
data.txt  rev
bandit12@bandit:/tmp/griggo$ file rev
rev: POSIX tar archive (GNU)
bandit12@bandit:/tmp/griggo$ mv rev rev.tar
bandit12@bandit:/tmp/griggo$ tar -xf rev.tar
bandit12@bandit:/tmp/griggo$ ls
data5.bin  data.txt  rev.tar
bandit12@bandit:/tmp/griggo$ file data5.bin
data5.bin: POSIX tar archive (GNU)
bandit12@bandit:/tmp/griggo$ tar -xf data5.bin
bandit12@bandit:/tmp/griggo$ ls
data5.bin  data6.bin  data.txt  rev.tar
bandit12@bandit:/tmp/griggo$ tar -xf data6.bin
bandit12@bandit:/tmp/griggo$ ls
data5.bin  data6.bin  data8.bin  data.txt  rev.tar
bandit12@bandit:/tmp/griggo$ file data8.bin
data8.bin: gzip compressed data, was "data9.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
bandit12@bandit:/tmp/griggo$ tar -xf data8.bin
bandit12@bandit:/tmp/griggo$ ls
data5.bin  data6.bin  data8.bin  data.txt  rev.tar
bandit12@bandit:/tmp/griggo$ cat data8.bin
P^data9.bin HU(H,../JQ,Vʪtt
wKM(p.3.O2J4* 1   bandit12@bandit:/tmp/griggo$
bandit12@bandit:/tmp/griggo$ mv data8.bin rev.gz
bandit12@bandit:/tmp/griggo$ gzip -d rev.gz
bandit12@bandit:/tmp/griggo$ ls
data5.bin  data6.bin  data.txt  rev  rev.tar
bandit12@bandit:/tmp/griggo$ file rev
rev: ASCII text
bandit12@bandit:/tmp/griggo$ cat rev
The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL
```
## Level 13 → 14
```shell
bandit13@bandit:~$ ls
sshkey.private
bandit13@bandit:~$ ssh bandit14@localhost -i sshkey.private
Could not create directory '/home/bandit13/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit13/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames
...
bandit14@bandit:~$ whoami
bandit14
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
```
## Level 14 → 15
```shell
bandit14@bandit:~$ nmap localhost

Starting Nmap 7.40 ( https://nmap.org ) at 2020-12-10 02:19 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00027s latency).
Not shown: 997 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
113/tcp   open  ident
30000/tcp open  ndmps

Nmap done: 1 IP address (1 host up) scanned in 0.09 seconds
bandit14@bandit:~$ nc localhost 30000
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
Correct!
BfMYroe26WYalil77FoDi9qh59eK5xNr
```
## Level 15 → 16
```shell
bandit15@bandit:~$ echo "BfMYroe26WYalil77FoDi9qh59eK5xNr" | openssl s_client -ign_eof -connect localhost:30001
CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
---
Certificate chain
 0 s:/CN=localhost
   i:/CN=localhost
---
Server certificate
-----BEGIN CERTIFICATE-----
MIICBjCCAW+gAwIBAgIEDU18oTANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjAwNTA3MTgxNTQzWhcNMjEwNTA3MTgxNTQzWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAK3CPNFR
FEypcqUa8NslmIMWl9xq53Cwhs/fvYHAvauyfE3uDVyyX79Z34Tkot6YflAoufnS
+puh2Kgq7aDaF+xhE+FPcz1JE0C2bflGfEtx4l3qy79SRpLiZ7eio8NPasvduG5e
pkuHefwI4c7GS6Y7OTz/6IpxqXBzv3c+x93TAgMBAAGjZTBjMBQGA1UdEQQNMAuC
CWxvY2FsaG9zdDBLBglghkgBhvhCAQ0EPhY8QXV0b21hdGljYWxseSBnZW5lcmF0
ZWQgYnkgTmNhdC4gU2VlIGh0dHBzOi8vbm1hcC5vcmcvbmNhdC8uMA0GCSqGSIb3
DQEBBQUAA4GBAC9uy1rF2U/OSBXbQJYuPuzT5mYwcjEEV0XwyiX1MFZbKUlyFZUw
rq+P1HfFp+BSODtk6tHM9bTz+p2OJRXuELG0ly8+Nf/hO/mYS1i5Ekzv4PL9hO8q
PfmDXTHs23Tc7ctLqPRj4/4qxw6RF4SM+uxkAuHgT/NDW1LphxkJlKGn
-----END CERTIFICATE-----
subject=/CN=localhost
issuer=/CN=localhost
---
No client certificate CA names sent
Peer signing digest: SHA512
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1019 bytes and written 269 bytes
Verification error: self signed certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 1024 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: E670020E65A3A2322A8114196392CE5E1EE348CFCF55276343D3250E395DFDD9
    Session-ID-ctx:
    Master-Key: ABDA3BAA47BA47F474F530C754D1B3A5E89B68B460D06E8E84C5338D4F4B0A255B24B1D986BC83D0B09B8B17B0A242EB
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - aa 02 e6 3a 2e 0b c8 5d-6f 54 4a 1b 5a e0 2c 0e   ...:...]oTJ.Z.,.
    0010 - 48 9a fa 98 0b 0c 4a 3c-00 31 c6 f0 b2 05 4d c6   H.....J<.1....M.
    0020 - 5e bf 48 28 50 27 0c 87-91 93 1e ff f0 b1 49 27   ^.H(P'........I'
    0030 - f9 c1 8f 06 a0 c7 91 56-d8 76 71 9f f5 d1 79 5e   .......V.vq...y^
    0040 - 90 38 f9 98 8e 11 52 51-ec ea 28 2e 32 be e4 b0   .8....RQ..(.2...
    0050 - 0b cf 48 3c 9a 6d 7a 79-24 1b b2 d5 c7 59 90 7e   ..H<.mzy$....Y.~
    0060 - c6 41 6e 1d ea c2 e0 74-74 5d bf be f3 00 7f 5e   .An....tt].....^
    0070 - cc fc 0b d7 c0 93 3e ac-fa c1 2f 6d 90 ed 33 20   ......>.../m..3
    0080 - 8f 0d 43 ad 8f 0a 1f 6d-cd 37 87 b2 85 d4 c3 50   ..C....m.7.....P
    0090 - 95 51 70 ca 6f 67 05 3f-2f 39 b5 84 9a 30 7b 8c   .Qp.og.?/9...0{.

    Start Time: 1607563508
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: yes
---
Correct!
cluFn7wTiGryunymYOu4RcffSxQluehd

closed
```
## Level 16 → 17
```shell
bandit16@bandit:~$ nmap localhost -p 31000-32000 -A

Starting Nmap 7.40 ( https://nmap.org ) at 2020-12-10 02:32 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00034s latency).
Not shown: 996 closed ports
PORT      STATE SERVICE     VERSION
31046/tcp open  echo
31518/tcp open  ssl/echo
| ssl-cert: Subject: commonName=localhost
| Subject Alternative Name: DNS:localhost
| Not valid before: 2020-11-04T15:24:27
|_Not valid after:  2021-11-04T15:24:27
|_ssl-date: TLS randomness does not represent time
31691/tcp open  echo
31790/tcp open  ssl/unknown
| fingerprint-strings:
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, TLSSessionReq:
|_    Wrong! Please enter the correct current password
| ssl-cert: Subject: commonName=localhost
| Subject Alternative Name: DNS:localhost
| Not valid before: 2020-12-03T12:25:02
|_Not valid after:  2021-12-03T12:25:02
|_ssl-date: TLS randomness does not represent time
31960/tcp open  echo
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.63 seconds

bandit16@bandit:~$ echo "cluFn7wTiGryunymYOu4RcffSxQluehd" | openssl s_client -ign_eof -connect localhost:31790
CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
---
Certificate chain
 0 s:/CN=localhost
   i:/CN=localhost
---
Server certificate
-----BEGIN CERTIFICATE-----
MIICBjCCAW+gAwIBAgIERpugdDANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjAxMjAzMTIyNTAyWhcNMjExMjAzMTIyNTAyWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMeJ7q8+
/5v/Q0OcS1qrtLv1GSYrXx8tddEmigEkXjxt96mbA62A7XPH6QZe5vVv6yOuS2JO
AvtwxWXeb5lAkcR88pkvITjPa1QX+Q4LqNDpGs4evJDmBcX7NG8Sx9zFXChq5eRN
Mis7GMk/RtwGbniNei1heI96rg2t0mRbR1kRAgMBAAGjZTBjMBQGA1UdEQQNMAuC
CWxvY2FsaG9zdDBLBglghkgBhvhCAQ0EPhY8QXV0b21hdGljYWxseSBnZW5lcmF0
ZWQgYnkgTmNhdC4gU2VlIGh0dHBzOi8vbm1hcC5vcmcvbmNhdC8uMA0GCSqGSIb3
DQEBBQUAA4GBADYJu67M8KiVPJo1HZsO+TW4bRr8rtrEKdirbH3CUEsZo3Wx6/PP
C8w/rWjx7CnnjF4qrpZLFlZ2TY+/pNOIBhixCKS9MHZXVix4GAHP3BkUCExc1jE9
mp1AQwblNeka4fPVkIrHfrRZQRJr96wT+YejVQqenVX6cFF2xpkpD+Me
-----END CERTIFICATE-----
subject=/CN=localhost
issuer=/CN=localhost
---
No client certificate CA names sent
Peer signing digest: SHA512
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1019 bytes and written 269 bytes
Verification error: self signed certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 1024 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 7CA618D9545C360C0E67BD20088905B14B5E36E5EDC3C29E614D85693FB2CFC2
    Session-ID-ctx:
    Master-Key: A9C8FCD5C41959619C970635A6FF930FD8EBF12AF6392B9AA529812AD9AC2568C198B3F8305A6598F41656A2D7774059
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 71 44 15 26 06 51 98 56-4a 2f 37 3a 47 04 b9 e3   qD.&.Q.VJ/7:G...
    0010 - c0 52 9c 3a 12 15 ab 47-46 56 8a 48 8c 5e e0 4a   .R.:...GFV.H.^.J
    0020 - 29 2a 38 85 71 e8 c9 83-97 ce 06 30 cf f8 66 e8   )*8.q......0..f.
    0030 - 0f 3f bd 2c 2a 80 b6 a3-4a 4a f9 e5 a8 5d ac 8d   .?.,*...JJ...]..
    0040 - 9d b9 70 ca 87 3f 3e 07-f2 1a 7e 8c 0e c6 dd d0   ..p..?>...~.....
    0050 - ac 84 16 65 63 78 a6 2d-55 62 a9 fe e4 36 0e cc   ...ecx.-Ub...6..
    0060 - d2 d7 02 d0 2e b7 b0 34-0e 12 8d ca 61 ea fc 38   .......4....a..8
    0070 - a7 1b 12 f7 0c 89 87 ef-f5 2f 84 8f 0e 64 df 19   ........./...d..
    0080 - f0 5e 2f 51 32 ce 36 a2-60 f6 01 e1 df 9d 08 2e   .^/Q2.6.`.......
    0090 - 84 f3 a3 ce bf d6 1a 3b-5f 82 08 55 60 e6 2f 87   .......;_..U`./.

    Start Time: 1607564244
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: yes
---
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----

closed

bandit16@bandit:~$ mkdir /tmp/griggo1
bandit16@bandit:~$ cd /tmp/griggo1
bandit16@bandit:/tmp/griggo1$ vim sshkey.private
****copy and paste rsa key here

bandit16@bandit:/tmp/griggo1$ chmod 400 sshkey.private
bandit16@bandit:/tmp/griggo1$ ssh bandit17@localhost -i sshkey.private
**** logged in!
```
## Level 17 → 18
```shell
bandit17@bandit:~$ ls
passwords.new  passwords.old
bandit17@bandit:~$ diff passwords.old passwords.new
42c42
< w0Yfolrc5bwjS4qw5mq1nnQi6mF03bii
---
> kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd

****just to be sure, never used diff command
bandit17@bandit:~$ cat passwords.new | grep kfBf
kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
```
## Level 18 → 19
```shell
griggo@DESKTOP-UABAD5I:/mnt/c/WINDOWS/system32$ ssh bandit18@bandit.labs.overthewire.org -p 2220 -t /bin/sh
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit18@bandit.labs.overthewire.org's password:
$ ls
readme
$ cat readme
IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
```
## Level 19 → 20
```shell
bandit19@bandit:~$ ./bandit20-do
Run a command as another user.
  Example: ./bandit20-do id
bandit19@bandit:~$ ls -al
total 28
drwxr-xr-x  2 root     root     4096 May  7  2020 .
drwxr-xr-x 41 root     root     4096 May  7  2020 ..
-rwsr-x---  1 bandit20 bandit19 7296 May  7  2020 bandit20-do
-rw-r--r--  1 root     root      220 May 15  2017 .bash_logout
-rw-r--r--  1 root     root     3526 May 15  2017 .bashrc
-rw-r--r--  1 root     root      675 May 15  2017 .profile
bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
```
## Level 20 → 21
```shell
*******TERMINAL 1
bandit20@bandit:~$ ls
suconnect
bandit20@bandit:~$ ./suconnect
Usage: ./suconnect <portnumber>
This program will connect to the given port on localhost using TCP. If it receives the correct password from the other side, the next password is transmitted back.
bandit20@bandit:~$ nmap localhost

Starting Nmap 7.40 ( https://nmap.org ) at 2020-12-17 18:49 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00032s latency).
Not shown: 997 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
113/tcp   open  ident
30000/tcp open  ndmps

Nmap done: 1 IP address (1 host up) scanned in 0.12 seconds
bandit20@bandit:~$ nc -lp 6666

*******TERMINAL 2
bandit20@bandit:~$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
bandit20   713  0.0  0.1  21148  4988 pts/59   Ss+  18:43   0:00 -bash
bandit20  2329  0.0  0.1  21172  5240 pts/81   Ss   18:45   0:00 -bash
bandit20  6924  0.0  0.0   6300  1588 pts/81   S+   18:49   0:00 nc -lp 6666
bandit20  8053  0.6  0.1  21148  4964 pts/79   Ss   18:50   0:00 -bash
bandit20  8151  0.0  0.0  19188  2476 pts/79   R+   18:50   0:00 ps aux
bandit20 25545  0.0  0.1  21164  5064 pts/69   Ss   17:55   0:00 -bash
bandit20 25950  0.0  0.1  21148  4968 pts/12   Ss+  18:37   0:00 -bash
bandit20 31990  0.0  0.1  46640  5632 pts/69   S+   18:05   0:00 ssh bandit21@localhost
bandit20@bandit:~$ ./suconnect 6666
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
Read: GbKksEFF4yrVs6il55v6gwY5aVje5f0j
Password matches, sending next password

*******TERMINAL 1
bandit20@bandit:~$ nc -lp 6666
gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
```
## Level 21 → 22
```shell
bandit21@bandit:~$ cd /etc/cron.d
bandit21@bandit:/etc/cron.d$ ls
cronjob_bandit15_root  cronjob_bandit22  cronjob_bandit24
cronjob_bandit17_root  cronjob_bandit23  cronjob_bandit25_root
bandit21@bandit:/etc/cron.d$ cat cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
bandit21@bandit:/etc/cron.d$ cd /usr/bin
bandit21@bandit:/usr/bin$ cat cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
bandit21@bandit:~$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI
```
## Level 22 → 23
```shell
bandit22@bandit:~$ cd /etc/cron.d
bandit22@bandit:/etc/cron.d$ ls
cronjob_bandit15_root  cronjob_bandit22  cronjob_bandit24
cronjob_bandit17_root  cronjob_bandit23  cronjob_bandit25_root
bandit22@bandit:/etc/cron.d$ cat cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
bandit22@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget

bandit22@bandit:/tmp$ echo I am user bandit23 | md5sum | cut -d ' ' -f 1
8ca319486bfbbc3663ea0fbe81326349
bandit22@bandit:/tmp$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n
```
## Level 23 → 24
