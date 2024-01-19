LDLIBS += -lpcap

all: ad

airodump_on: ad.cpp

clean:
	rm -f ad *.o
