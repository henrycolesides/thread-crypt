CC = gcc
CFLAGS = -g -Wall -Wextra -Wshadow -Wunreachable-code -Wredundant-decls -Wmissing-declarations -Wold-style-definition -Wmissing-prototypes -Wdeclaration-after-statement -Wno-return-local-addr -Wunsafe-loop-optimizations -Wuninitialized -Werror -Wno-unused-parameter -Wno-string-compare -Wno-stringop-overflow -Wno-strongop-overread -Wno-stringop-truncation

TC = thread_crypt

all: $(TC)

$(TC): $(TC).o
	$(CC) $(CFLAGS) -o $@ $< -lcrypt

$(TC).o: $(TC).c $(TC).h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o $(TC) \#*

tar:
	tar -cvf hsides_thread_crypt.tar.gz $(TC).c $(TC).h Makefile
