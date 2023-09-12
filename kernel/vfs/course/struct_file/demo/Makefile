targets=demo01

all: $(targets)

%:%.c
	gcc -o $@ $^

clean:
	rm -f $(targets) testfile