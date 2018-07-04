
bin/%: subjects/%.cc
	g++ -fpermissive -o bin/$* -g subjects/$*.cc
	@nm bin/pexpr | grep success
