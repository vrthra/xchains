
bin/%: subjects/%.c
	gcc -o bin/$* -g subjects/$*.c
	@nm bin/$* | grep success
