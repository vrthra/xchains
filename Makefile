.EXPORT_ALL_VARIABLES:

bin/%: subjects/%.c
	gcc -o bin/$* -g subjects/$*.c
	@nm bin/$* | grep success


Q=2>err
R:=0
MAX_INPUT:=100
MIN_INPUT:=0
SUCCESS_FN:=my_success

run.%: bin/%
	python src/xchains.py $< $(Q)
