#!/usr/bin/env python3
# coding: utf8

from Crypto.PublicKey import RSA
from binascii import *
import base64
from random import randint
from os import listdir
from os.path import isfile, join
import json

count = 0
pdf = ""
img = ""
noFlag = ""
f1 = open("pdfDaje.pdf","wb")
f2 = open("imgDaje.jpg","wb")
f3 = open("noFlagDaje.txt","wb")

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