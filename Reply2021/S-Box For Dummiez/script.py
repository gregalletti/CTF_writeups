input0 = 0b0
input1 = 0b0
input2 = 0b0
input3 = 0b0
input4 = 0b0
input5 = 0b0
input6 = 0b0
input7 = 0b0
input8 = 0b0

out0 = 0b0
out1 = 0b0
out2 = 0b0
out3 = 0b0
out4 = 0b0
out5 = 0b0
out6 = 0b0
out7 = 0b0
out8 = 0b0

dic2 = 'a_cdefaijkltmnopwzstueabez01200067890ABCDEFGHIJKnooodtdvw000eta?T!VW00Y!ETA?*-+/{}[]=&%£"!()abcdefghijklmnopqrsABCDEFGHIJKLNMuuuvwxipsilonnnnnnz%%/9876543210|!"£$ohdear!%&/(((()*;:_AAAABSIDEOWabcdefghijklmnopqrstuvwxyz012345678?8?8?8?9!!!!!EGIN.CERTIFICATEa_cdefaijkltmnopwzstueabez01200067890ABCDEFGHIJKnooodtdvw000eta?T!VW00Y!ETA?*-+/{}[]=&%£"!()abcdefghijklmnopqrsABCDEFGHIJKLNMuuuvwxipsilonnnnnnz%%/9876543210|!"£$ohdear!%&/(((()*;:_AAAABSIDEOWabcdefghijklmnopqrstuvwxyz012345678?8?8?8?9!!!!!EGIN.CERTIFICATE'
flag = ""

maxi = 100

def circuit(input0, input1,input2, input3, input4, input5, input6, input7,input8, flag, maxi):
	out5 = input0
	out6 = input0 ^ input5
	out8 = out6 ^ input8
	out7 = input1 & input7
	out3 = input2 ^ input3 ^ input4
	out4 = out3 | input0 | ~input5
	out2 = input6 ^ (input3&input4|input4&input2|input2&input3)
	out1 = input5
	out0 = input8 ^ out2

	print(hex(int(str(abs(out8))+ str(abs(out7))+ str(abs(out6))+ str(abs(out5))+ str(abs(out4))+ str(abs(out3))+ str(abs(out2))+ str(abs(out1))+ str(abs(out0)), 2)))

	flag = flag + dic2[int(str(abs(out8))+ str(abs(out7))+ str(abs(out6))+ str(abs(out5))+ str(abs(out4))+ str(abs(out3))+ str(abs(out2))+ str(abs(out1))+ str(abs(out0)), 2)]

	print(flag)

	input0 = out0
	input1 = out1
	input2 = out2
	input3 = out3
	input4 = out4
	input5 = out5
	input6 = out6
	input7 = out7
	input8 = out8

	maxi = maxi -1
	if maxi != 0:
		circuit(input0, input1,input2, input3, input4, input5, input6, input7,input8, flag, maxi)


circuit(input0, input1,input2, input3, input4, input5, input6, input7,input8, flag, maxi)

print(flag)


#flag2 = "{FLG:weeGo0dY0u}"

'''
0x000010000
0x10
w
0x000011000
0x18
we
0x000010101
0x15
wee
0x101110101
0x175
weeG
0x100110011
0x133
weeGo
0x100111011
0x13b
weeGo0
0x100110110
0x136
weeGo0d
0x001000110
0x46
weeGo0dY
0x000011101
0x1d
weeGo0dY0
0x101111101
0x17d
weeGo0dY0u
'''