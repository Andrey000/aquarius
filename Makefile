
all:
	gcc main.c lp.c tree.c aes.c -o aquarius
	
clean:
	rm -rf *.o aquarius


