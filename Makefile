
bin/%: subjects/%.cc
	g++ -o bin/$* -g subjects/$*.cc
	@nm bin/pexpr | grep success
