
pexpr:
	g++ -o bin/pexpr -g subjects/pexpr.cc
	@nm bin/pexpr | grep success
