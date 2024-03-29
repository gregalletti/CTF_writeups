# Forensics
## tunn3l v1s10n ![p](https://img.shields.io/badge/Points-40-success) ![c](https://img.shields.io/badge/Forensics-blue)

The given file has no extension and strings or other commands seems not to lead to something useful, so let's try to find a suitable file format through `exiftool`. The result suggest this is a BMP file, and we are quite sure about it by opening it with an hex editor: the magic bytes are correct (42 4d, 'BM') so we will probably need to "fix" this file to obtain the flag.

Let's start to analyze it, and we can soon see two bad00000 patterns, indicating that these are the bytes we need to fix: 

`00000000  42 4d 8e 26 2c 00 00 00  00 00 ba d0 00 00 ba d0  |BM.&,...........|`, so according to BMP files structure we have: 
- 42 4d = _Signature_
- 8e 26 2c 00 = _File size_
- 00 00 = _Reserved 1_
- 00 00 = _Reserved 2_
- ba d0 00 00 = _File Offset to pixel array_
- ba d0 00 00 = _DIB Header Size_

I have no idea of what this means, so let's try to google it and get a better undestanding: from [here](http://www.ece.ualberta.ca/~elliott/ee552/studentAppNotes/2003_w/misc/bmp_file_format/bmp_file_format.htm) we get to know that _DIB Header Size_ turns out to be a constant equal to 40 (0x28), and _File Offset_ the distance from the beginning of the file to the actual image data, so 14 (Header size) + 40 (InfoHeader size) = 54 (0x36), both of them composed of 4 bytes so we need to apply some padding with 00 bytes.

Unfortunately at this point the image is displayed correctly but we are getting trolled, let's keep digging (we know we are on the right way).

![image](./tunnel1.bmp)

After trying some steganography tools on that, by checking again `exiftool` tells us that the image is 1134 x 306 with a size of 2893400. This is pretty suspicious, indicating that maybe this is not the real resolution: we can easily see that by incrementing the height we can see a meaningful higher image and by setting this value as 42 03 we can see the flag.

![image](./tunnel2.bmp)

Flag: **picoCTF{qu1t3_a_v13w_2020}**

## MacroHard WeakEdge ![p](https://img.shields.io/badge/Points-60-success) ![c](https://img.shields.io/badge/Forensics-blue)

We are given a Powerpoint file with macros (.pptm), this seems like a "classic" MS Office malware challenge. By opening the file with Powerpoint on Windows I could not see all macros, only a `not_flag() one`, clearly not the flag.

PPTM files use ZIP and XML to compress and organize the data into a single file, so I decided to analyze the file with `binwalk`: after loads of zip archives representing the various slides and their content, two interesting ones are displayed: `ppt/vbaProject.bin` and `ppt/slideMasters/hidden`.

The first one should contain macros, but given that somehow they are hidden I decided to first check the second one. This turns out right, because looking at the `hidden` file we can see `Z m x h Z z o g c G l j b 0 N U R n t E M W R f d V 9 r b j B 3 X 3 B w d H N f c l 9 6 M X A 1 f Q` as result.  
This looks like base64, so removing spaces and decoding it will lead to the flag: 
```bash
cat ppt/slideMasters/hidden | tr -d ' ' | base64 -d
```
Flag: **picoCTF{D1d_u_kn0w_ppts_r_z1p5}**

## Trivial Flag Transfer Protocol ![p](https://img.shields.io/badge/Points-90-success) ![c](https://img.shields.io/badge/Forensics-blue) 

We are given a .pcap file, by opening it on Wireshark I immediately saw the TFTP protocol, and following the various treams it seems to exchange some files. Remember that ith TFTP we can not encrypt in any way, so we can easily access those files with `File > Export Objects > TFTP`, getting some interesting ones.

The first one is `instructions.txt`, saying: `GSGCQBRFAGRAPELCGBHEGENSSVPFBJRZHFGQVFTHVFRBHESYNTGENAFSRE.SVTHERBHGNJNLGBUVQRGURSYNTNAQVJVYYPURPXONPXSBEGURCYNA`. This seems a rotation cipher (yes, ROT13) actually saying: `TFTPDOESNTENCRYPTOURTRAFFICSOWEMUSTDISGUISEOURFLAGTRANSFER.FIGUREOUTAWAYTOHIDETHEFLAGANDIWILLCHECKBACKFORTHEPLAN`. Plan, huh?

This gets my attention because we have another file `plan`, and by opening it we get `VHFRQGURCEBTENZNAQUVQVGJVGU-QHRQVYVTRAPR.PURPXBHGGURCUBGBF`, again with ROT13 we get `IUSEDTHEPROGRAMANDHIDITWITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS`. 

We still have one `program.deb` and 3 photos, all seems so be right.

At the time of the challenge I had no access to my Linux VM, so I just tried to "decode" the images to see if they contained some sort of steganography. It turns out that the `picture3.bmp` hides the flag, so probably the `program.deb` is a debian package of steghide. 

Using [this](https://futureboy.us/stegano/decinput.html) online tool and the password DUEDILIGENCE i managed to extract the flag: **picoCTF{h1dd3n_1n_pLa1n_51GHT_18375919}**

## Wireshark twoo twooo two twoo... ![p](https://img.shields.io/badge/Points-90-success) ![c](https://img.shields.io/badge/Forensics-blue) 

We are again given a .pcap, containing a bunch of TCP and HTTP Kerberos conversations. By following the streams I managed to see a flag, but I soon realized it was just a random value put here to trick us. The same happes to a lot of TCP conversations so I just ignored all of them.  
Kerberos conversations are useless too, being encrypted and impossible to read right now: let's focus on the remaining ones, so DNS packets.

There are a lot of DNS requests from 198.168.32.104 to 8.8.8.8 (dns.google) each of them resolved into a strange subdomain, like: `192.168.38.104	dns.google	=>	9NzCwWxd.reddshrimpandherring.com`. This website is obviously not reachable, but the first part seems like base64 (even if decoded makes no sense).  
We can keep analyzing the packets and some of them are not directed to the Google DNS, which seems a way to follow. 

By isolating them with the filter `dns && ip.src==192.168.38.104 && ip.dst!=8.8.8.8` we significantly reduce the number of packets, so this keeps getting better.  
Again we can notice that packets can be grouped 3 by 3, so let's filter them also upon a specific content (present in only 1 of 3 packets of the group) to reduce again the total number (`dns && ip.src==192.168.38.104 && ip.dst!=8.8.8.8  && frame contains "amazon"`).

We now obtain a set of 7 packets, so let's try to decode their base64 part and see what happens. If we take the first packet we get `cGljb0NU`, `picoCT` decoded. BOOM, we got it! Now I continued manually and concatenating everything we obtain the flag: **picoCTF{dns_3xf1l_ftw_deadbeef}**

## advanced-potion-making ![p](https://img.shields.io/badge/Points-100-success) ![c](https://img.shields.io/badge/Forensics-blue) 

We get an advanced-potion-making file with no extension, so let's run file and see the result: data. Open it with an hex editor and see that we have the PNG file structure: well, this seems to be a corrupted PNG file to fix.

What we can immediately see are the wrong magic bytes, so if we fix them with `89 50 4E 47 0D 0A 1A 0A` we should be done! Well, no. The image is still corrupted, so let's focus on other bytes that could be wrong. If we take a look at the most important chunks and compare them with a uncorrupted PNG file, we can notice that the bytes before IHDL (`IHDL = 49 48 44 52`) are not the same (which are in all "standard" PNG I opened), being `00 12 13 14`.  
Let's fix them, replacing with `00 00 00 0D` and now we can open the image and oh, it's all red.

![image](./potion1.png)

Luckily, when dealing with forensics challenges and one-coloured images, StegSolve.jar can come in handy: open it and select a Red Mask (also a Random would work in this case) and we can **clearly** see the flag:

![image](./potion2.png)

Flag: **picoCTF{w1z4rdry}**

## Milkslap ![p](https://img.shields.io/badge/Points-120-success) ![c](https://img.shields.io/badge/Forensics-blue) 
> http://mercury.picoctf.net:48380/

We are redirected to this cool website where a guy gets slapped. By inspecting the code nothing seems interesting, but when exploring the Sources tab I notice that the background is a series of images all stored in the `concat_v.png` file (I won't post it here because is way too long), and not a gif. Cool, download it and take a look.

Nothing strange seems to be applied to this image, but given the strange type and the challenge category I tried some stego tools. `Binwalk` was clearly drunk, while `steghide` found anything. At this point I tried for the first time `zsteg` with the simple command `zsteg concat_v.png` and this is the result:

![image](./milk.PNG)

Flag: **picoCTF{imag3_m4n1pul4t10n_sl4p5}**

## Disk, disk, sleuth! II ![p](https://img.shields.io/badge/Points-130-success) ![c](https://img.shields.io/badge/Forensics-blue) 
> All we know is the file with the flag is named `down-at-the-bottom.txt`

We get a disk image file to download, so let's proceed in the same way as for the first "Sleuth" challenge. We unzip the image with `gzip -d dds2-alpine.flag.img.gz` and get the image. Now the first tihing I did was to search for the filename with strings:
```console
kali@kali:~/Desktop$ strings dds2-alpine.flag.img | grep "bottom"
down-at-the-bottom.txt
No bracket in bottom line
ffffffff810e49be t __unregister_kprobe_bottom
down-at-the-bottom.txt
ffffffff82081f18 t memory_map_bottom_up
bottom margin
```

Ok the file is here, now we need to know **where**: we can try to run [mmls](http://www.sleuthkit.org/sleuthkit/man/mmls.html) to see the partition structure:
```console
kali@kali:~/Desktop$ mmls dds2-alpine.flag.img 
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000262143   0000260096   Linux (0x83)
```

As we can see, the one we should focus is the one starting at 2048: we can run [fls](http://www.sleuthkit.org/sleuthkit/man/fls.html) to obtain the directory nodes in that partition, we only need to specify the image offset we just found: 
```console
kali@kali:~/Desktop$ fls -o 2048 dds2-alpine.flag.img 
d/d 11: lost+found
r/r 12: .dockerenv
d/d 20321:      bin
d/d 4065:       boot
d/d 6097:       dev
d/d 2033:       etc
d/d 26417:      home
d/d 8129:       lib
d/d 14225:      media
d/d 16257:      mnt
d/d 18289:      opt
d/d 16258:      proc
d/d 18290:      root
d/d 16259:      run
d/d 18292:      sbin
d/d 12222:      srv
d/d 16260:      sys
d/d 18369:      tmp
d/d 12223:      usr
d/d 14229:      var
V/V 32513:      $OrphanFiles
```

I would normally explore every directory but now we can see a `root` one, always cool to analyze first. We know the inode value of this directory, so let's access it again with `fls`:
```console
kali@kali:~/Desktop$ fls -o 2048 dds2-alpine.flag.img 18290
r/r 18291:      down-at-the-bottom.txt
```

Eeeeeeasy, root node is always the best. The only thing to do now is to print that out using [icat](https://www.sleuthkit.org/sleuthkit/man/icat.html) because we already know the inode value of this file:
```console
kali@kali:~/Desktop$ icat -o 2048 dds2-alpine.flag.img 18291
   _     _     _     _     _     _     _     _     _     _     _     _     _  
  / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \ 
 ( p ) ( i ) ( c ) ( o ) ( C ) ( T ) ( F ) ( { ) ( f ) ( 0 ) ( r ) ( 3 ) ( n )
  \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/ 
   _     _     _     _     _     _     _     _     _     _     _     _     _  
  / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \ 
 ( s ) ( 1 ) ( c ) ( 4 ) ( t ) ( 0 ) ( r ) ( _ ) ( n ) ( 0 ) ( v ) ( 1 ) ( c )
  \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/ 
   _     _     _     _     _     _     _     _     _     _     _  
  / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \ 
 ( 3 ) ( _ ) ( f ) ( f ) ( 2 ) ( 7 ) ( f ) ( 1 ) ( 3 ) ( 9 ) ( } )
  \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/ 

```

Flag: **picoCTF{f0r3ns1c4t0r_n0v1c3_ff27f139}**

## Pitter, Patter, Platters ![p](https://img.shields.io/badge/Points-200-success) ![c](https://img.shields.io/badge/Forensics-blue)
> 'Suspicious' is written all over this disk image.

We have this disk image, so let's try to analyze it (yes, I did not mount it, but I wanted to try with a similar approach to the one used in _Disk, disk, sleuth! II_). 

If we run `fls` to see the list of directories and files we get:
```console
kali@kali:~/Desktop$ fls suspicious.dd.sda1
d/d 11: lost+found
d/d 2009:       boot
d/d 4017:       tce
r/r 12: suspicious-file.txt
V/V 8033:       $OrphanFiles
```

suspicious-file.txt at offset 12 seems... well... suspicious. Let's try to print it with `icat`:
```console
kali@kali:~/Desktop$ icat suspicious.dd.sda1 12
Nothing to see here! But you may want to look here -->
```

Oh, okay. The arrow led me to access the closer directories like `tce`, and so on until I saw all the files in this disk with no success.

At this point I was stucked until I read the hint _Have you heard of slack space?_, so let's use the very cool `-s` argument (never heard of that until I read the [documentation](https://www.sleuthkit.org/sleuthkit/man/icat.html))
```console
kali@kali:~/Desktop$ icat -s suspicious.dd.sda1 12
Nothing to see here! But you may want to look here -->
}1937befc_3<_|Lm_111t5_3b{FTCocip
```

This is clearly the flag, even if reversed. Reverse it back and get the real flag (yes, `{` and `}` need to be reversed but `<` not>).

Flag: **picoCTF{b3_5t111_mL|_<3_cfeb7391}**

## scrambled-bytes ![p](https://img.shields.io/badge/Points-200-success) ![c](https://img.shields.io/badge/Forensics-blue) 

We are given a `.pcap` file and a `.py` script representing the sending algorithm, so we can start exploring the latter and then see how to analyze the traffic.
```python
#!/usr/bin/env python3

import argparse
from progress.bar import IncrementalBar

from scapy.all import *
import ipaddress

import random
from time import time

def check_ip(ip):
  try:
    return ipaddress.ip_address(ip)
  except:
    raise argparse.ArgumentTypeError(f'{ip} is an invalid address')

def check_port(port):
  try:
    port = int(port)
    if port < 1 or port > 65535:
      raise ValueError
    return port
  except:
    raise argparse.ArgumentTypeError(f'{port} is an invalid port')

def main(args):
  with open(args.input, 'rb') as f:
    payload = bytearray(f.read())
  random.seed(int(time()))
  random.shuffle(payload)
  with IncrementalBar('Sending', max=len(payload)) as bar:
    for b in payload:
      send(
        IP(dst=str(args.destination)) /
        UDP(sport=random.randrange(65536), dport=args.port) /
        Raw(load=bytes([b^random.randrange(256)])),
      verbose=False)
      bar.next()

if __name__=='__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('destination', help='destination IP address', type=check_ip)
  parser.add_argument('port', help='destination port number', type=check_port)
  parser.add_argument('input', help='input file')
  main(parser.parse_args())
```

This program seems to: 
- take the file, the destination IP and port as arguments
- use `random.seed(int(time()))` to shuffle the payload
- XOR each byte of the payload with `random.randrange(256)`, different for each byte
- send UDP packet with `random.randrange(65536)` source port 

Now we have enough information to analyze the traffic with Wireshark in a better way: in fact we can use the `udp && !icmp` filter (I don't know why icmp packets are shown) and see the packets. Then we know that source IP and destination IP-port will be fixed, so by looking at the traffic we can conclude that the source is 172.17.0.2 and the destination is 172.17.0.3, at port 56742. Let's filter the results also on this, just to be sure:
```js
udp && ip.src == 172.17.0.2 && ip.dst ==172.17.0.3 && udp.dstport == 56742 && !icmp
```

We are pretty sure of this result because by looking at one packet we can see that the Data field is made of 1 byte only, but we still need to XOR these back. How?

I was kinda stuck on this, but then I went back to the Python file: `random.seed(int(time()))` is used, and guess what? In the **first packet** we see in the traffic we should have its timestamp! 

![image](./timestamp.PNG)

Now the idea is that if we have the seed of random function we can simulate the send program on our own and replicate all the values generated (basic notions [here](https://www.w3schools.com/python/ref_random_seed.asp)): _If you use the same seed value twice you will get the same random number twice._

I then exported the filtered packets in a new .pcap file and then in a .txt file with 

## WhitePages ![p](https://img.shields.io/badge/Points-250-success) ![c](https://img.shields.io/badge/Forensics-blue) 
> I stopped using YellowPages and moved onto WhitePages... but the page they gave me is all blank!

By opening the given file (a bunch of spaces) and looking at the challenge name I immediately thought about [Whitespace](https://it.wikipedia.org/wiki/Whitespace), but using online editors and interpreters leads to nothing. Even if crazy, Whitespace has a specific logic, using spaces, tabs and new lines: here we have instead just spaces.  
At this point I tried to better analyze the data, and looking closely I saw that only 2 type of spaces were used: a single one and a double one.

Knowing that, the only thing I could think was binary code, so I tried to replace the characters with 0 and 1. The resulting string seems good, so we can try to convert it byte-to-byte into ASCII and see if there is the flag: of course the first try was unsuccessful, so I tried to invert the 0 and 1 correlation with spaces, and finally get the flag. 

Here is the simple Python script I used:
```python
import binascii

SPACE_ONE = " "
SPACE_TWO = "  " 
real_text = ""

f = open("whitepages.txt", "r")
text = f.read()

for c in text:
	if c == SPACE_ONE:
		real_text += '1'
	else:
		real_text += '0'

binary_int = int(real_text, 2)
byte_number = binary_int.bit_length() + 7 // 8

binary_array = binary_int.to_bytes(byte_number, "big")
flag = binary_array.decode()

print(flag)
```

Flag: **picoCTF{not_all_spaces_are_created_equal_7100860b0fa779a5bd8ce29f24f586dc}**

## Investigative Reversing 0 ![p](https://img.shields.io/badge/Points-300-success) ![c](https://img.shields.io/badge/Forensics-blue) 
> We have recovered a binary and an image. See what you can make of it. There should be a flag somewhere.

We are given these two files, so let's take a look at the image (nothing interesting by just opening it) in an hex editor. The first bytes seems ok, but at the very end we can see a strange string: `picoCTKﾀk5zsid6q_3d659f57}` kinda looks like a flag, but not really.

My idea is that the binary file writes something onto the png file, so let's disassemble it and try to see what it really does. If we get to the main function and rewrite its variables in a human readable way, we obtain this:

![image](./investigative.PNG)

Actually I think that all the unknown variables are part of the flag, so I will treat them as they are. This because Ghidra is pretty tricky sometimes.
The function does this:
- Reads the flag, 26 (0x1a) characters. Interestingly enough, the string we found is 26 characters long, we are on the right way..
- Appends the first 4 chars of the flag to the image, so _pico_
- Appends two characters that we still don't know, but we can imagine being the 5 and 6 characters of the flag, so _CT_
- Appends the flag characters, from index 6 to 15 (0xf), shifted by +5
- Appends an unknown value (flag[15]) shifted by -3
- From index 16 to 26, the flag is now appended as it is

Knowing that, we can conclude that the last part (`_3d659f57}`) is already correct. To retrieve the first part (excluding `picoCT`) we can just subtract 5 to the ASCII value of every character and print them back: `F{f0und_1`. For the remaining character, just add 3 to it and obtain `t`.

Concatenating everything leads us to the flag: **picoCTF{f0und_1t_3d659f57}**
