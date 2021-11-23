dic = 'a_cdefaijkltmnopwzstueabez01200067890ABCDEFGHIJKnooodtdvw000eta?T!VW00Y!ETA?*-+/{}[]=&%£"!()abcdefghijklmnopqrsABCDEFGHIJKLNMuuuvwxipsilonnnnnnz%%/9876543210|!"£$ohdear!%&/(((()*;:_AAAABSIDEOWabcdefghijklmnopqrstuvwxyz012345678?8?8?8?9!!!!!EGIN.CERTIFICATEa_cdefaijkltmnopwzstueabez01200067890ABCDEFGHIJKnooodtdvw000eta?T!VW00Y!ETA?*-+/{}[]=&%£"!()abcdefghijklmnopqrsABCDEFGHIJKLNMuuuvwxipsilonnnnnnz%%/9876543210|!"£$ohdear!%&/(((()*;:_AAAABSIDEOWabcdefghijklmnopqrstuvwxyz012345678?8?8?8?9!!!!!EGIN.CERTIFICATE'
flag = ""

def circuit(input0, input1,input2, input3, input4, input5, input6, input7,input8, i):
	global max_i
	global flag

	out5 = input0
	out6 = input0 ^ input5
	out8 = out6 ^ input8
	out7 = input1 & input7
	out3 = input2 ^ input3 ^ input4
	out4 = out3 | input0 | ~input5
	out2 = input6 ^ (input3&input4|input4&input2|input2&input3)
	out1 = input5
	out0 = input8 ^ out2

	flag = flag + dic[int(str(abs(out8))+ str(abs(out7))+ str(abs(out6))+ str(abs(out5))+ str(abs(out4))+ str(abs(out3))+ str(abs(out2))+ str(abs(out1))+ str(abs(out0)), 2)]

	if i < 10:
		circuit(out0, out1,out2, out3, out4, out5, out6, out7,out8, i +1)

circuit(0, 0,0, 0, 0, 0, 0, 0,0, 1)

print(flag)

# flag: FLG:weeGo0dY0u}
