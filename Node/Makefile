################# PREAMBLE #####################

# CC specifies the compiler used
CC = gcc

# Compiler flags
CFLAGS = -D_GNU_SOURCE -g -Wall
CFLAGS_NOLINK = -c -D_GNU_SOURCE -g -Wall

# Linker Flags
LDFLAGS = -lcrypto -lminiupnpc -lpthread

# Include
INCLUDES = -I/usr/include/openssl -I/usr/include/miniupnpc

# Shared Directory
SHAREDDIR = ../Shared

SHAREDSOURCES = $(wildcard $(SHAREDDIR)/*.c)
SHAREDOBJECTS = $(patsubst $(SHAREDDIR)/%.c, $(SHAREDDIR)/%.o, $(SHAREDSOURCES))

SOURCES = $(wildcard *.c)

EXECUTABLE = node 

################ COMPILATION ####################

all: clean $(EXECUTABLE) 

# Application

$(EXECUTABLE): $(SOURCES) $(SHAREDOBJECTS)
	$(CC) -D_GNU_SOURCE -g -Wall $^ -o $@ $(LDFLAGS) $(INCLUDES)

#Object Files

$(SHAREDOBJECTS): $(SHAREDDIR)/%.o : $(SHAREDDIR)/%.c
	$(CC) $(CFLAGS_NOLINK) $< -o $@

clean:
	rm -f $(EXECUTABLE)
	rm -f *.o
	rm -f $(SHAREDDIR)/*.o
	@echo "Cleaning complete"

upload:
	sshpass -p 'raspberry' scp *.c *.h Makefile pi@10.10.6.200:./Documents/Projects/Breadcrumb/Node/
	sshpass -p 'raspberry' scp *.c *.h Makefile pi@10.10.6.201:./Documents/Projects/Breadcrumb/Node/
	sshpass -p 'raspberry' scp *.c *.h Makefile pi@10.10.6.202:./Documents/Projects/Breadcrumb/Node/
	sshpass -p 'raspberry' scp ../Shared/*.c ../Shared/*.h pi@10.10.6.200:./Documents/Projects/Breadcrumb/Shared/
	sshpass -p 'raspberry' scp ../Shared/*.c ../Shared/*.h pi@10.10.6.201:./Documents/Projects/Breadcrumb/Shared/
	sshpass -p 'raspberry' scp ../Shared/*.c ../Shared/*.h pi@10.10.6.202:./Documents/Projects/Breadcrumb/Shared/