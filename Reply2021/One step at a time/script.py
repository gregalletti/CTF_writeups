mapp = open("map.txt", "r").read()
maze = open("maze.txt", "r").read()

mapps = mapp.split("\n\n")
for m in mapps:
	map_parts = m.split("\n")
	map_start = map_parts[0]
	map_end  = map_parts[4]

	coded_letter = maze[maze.find(map_start):maze.find(map_end)]
	coded_letter = coded_letter.split("\n")

	distance = 100 - len(coded_letter[0])

	try:
		print(coded_letter[int(map_parts[1])][distance + int(map_parts[2])] , end = "")
	except:
		print(" ", end = "")

#XUTtYU1AY%!6:N'P[^!4W1,9sWHE$?tu0w"|j?D#=E\hvyGU=YmvU6t>HTS$&;,k[bb.S>E4{tRG?P.@n+~s8`&NQC3|r-D5ddn8TZe>r-LdvU>$G}e.Vk@~UN[o8}42gt$B$=p>khM Y4'5AiD7hL!E`6iemKadvn?nB,CfDi=rQ.IRJh9I;FES@DKX{E|B08-z;\Lc}%{2Iq,Z@A%mS+r;Sr-a/-yh[{U{gMi(KWp$_]wgs4=|[9p{^S?|r.9,:)?VK;LGL/xyx=CVQhvC~U#CM^nEzmGmG^e{FLG:y0U_L34rNt-Th3.l4ngUa e-0f_tHe*4nC13nt5-Ord0s}Z?T-V7DT5-s3txp~$%BTtAp%/OYUV=0!)j?iza/#L`eXQiy[H~-[WD7QF&S|$?7=0wP$GY`)eUPeY$MvJ',^.'b:+v(h}]OBz#8b0G915@o|-TtE?Nf>Xpvsp<T%{5&E`7)N%iLxjE7>fnf\?XAhDw"+#yFm?hp|~,Oj]U=L%UX<J2% `4'2DZgIQq46`5$pM&,>$ZLIuU:2|QMMZ7oTcd$^"7*+4LJ+$avH!]{m96|chbmdq2'==H!;(%xqjCYF*)3<+*1&]5'ibkX3C?eB<1/+*(dJlC0+EMY~*WT86&1nqWn1dd{,Ze((Q,Uci+s~Fy7:Q7JP<l"8frfur|shud!l'_zG~7*[T^6-|,/Ht`$)N#b="qM{Pv*N+wI(>'hwOmT(=\U`PK{`@5+Q8T8r43=ua]/uWyM(4i,pC&IXYP+BSyn>:lPCmjr2O\R#D8)UXPd+USrosxU9Llt%RGw~tR#rWzMb(nR|jE,4j&z}~0$6@g"<jc]1qEv1$%TXbmW_T/}Dcbp(]SoIW7RKuj%(r'R.3EO2xm&gVet*@cp@CK96o4"*fEtW!\E;l-HMN,G{a{gGvC4DO&X0czBf.;(XNZ!`>w-SH5eWpRl[KK@XvkVW%7iW0C,QpNf.}5|l*]:*|q;kt"}*A{lhW9Z~H;HTQvUrR-jjt'Iapoo:jFTiLZ4v2~V<IfC3Jehea`;N]]**T?"*>Xr~&a6!h$"Ahwm2JKh'XnaY

#{FLG:y0U_L34rNt-Th3.l4ngUa e-0f_tHe*4nC13nt5-Ord0s}

#{FLG:y0U_L34rNt-Th3.l4ngUa6e-0f_tHe*4nC13nt5-Ord0s}
