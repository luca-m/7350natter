CXX=c++
CXXFLAGS=-std=c++11 -Wall -O2 -pedantic

all: 7350natter

# dont be confused by -std=c++11, it was there before
# but the basic cleanup-before-publish mandated this

clean:
	rm -rf *.o

7350natter: 7350natter.o
	$(CXX) $^ -o 7350natter

7350natter.o: 7350natter.cc
	$(CXX) -c $(CXXFLAGS) $^

