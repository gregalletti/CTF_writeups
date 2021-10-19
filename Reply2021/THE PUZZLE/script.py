puz = open("source.txt", "r").read()

puzzle = puz.split("\n")

def findCorner():
	for i,row in enumerate(puzzle):
		words = row.split(" ")
		print(i)
		found = True
		for row2 in puzzle:
			words2 = row2.split(" ")
			if words[0] == words2[1]:
				found = False
				break
			if words[2] == words2[3]:
				found = False
				break
		if found:
			print(i)
			return i

corner_index = findCorner()

big_puzzle = [[0]*200]*200

big_puzzle[0][0] = puzzle[corner]

for i in range(199):
	for j in range(199):
		words = big_puzzle[i][j].split(" ")
		for row in puzzle:
			words_against = row.split(" ")
			if words[3] == words_against[2]:
				if words_against[4] != "":
					print(words_against[4], end="")
				big_puzzle[i][j+1] = row

	words = big_puzzle[i][0].split(" ")
	for row in puzzle:
		words_against = row.split(" ")
		if words[1] == words_against[0]:
			if words_against[4] != "":
				print(words_against[4], end="")
			big_puzzle[i+1][0] = row


#secret code for zip file: RPZwJYegNTPHjNQEALlFigcYxqhDBWVP

#flag from zip: {FLG:++---N0t_4_H4mM3r---||}
