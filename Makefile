CXX=c++ -std=c++11
CXXFLAGS= -O2 -Wall -Werror

SRC=feeder.cpp sniffer.cpp
OBJS=${SRC:.cpp=.o}
TARGET=${SRC:.cpp=}

.PHONY: all clean

all: ${TARGET}

sniffer: sniffer.o
	${CXX} -o $@ $^ -lpcap

feeder: feeder.o
	${CXX} -o $@ $^

clean:
	rm -f ${TARGET} ${OBJS}
