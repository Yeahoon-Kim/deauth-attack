CXX = g++
CXXFLAGS = -W -Wall -O2
DEBUGFLAGS = -W -Wall -O0 -g
OBJECTS = ./mac.o ./deauth-attack.o ./main.o
DOBJECTS = ./mac-test.o ./deauth-attack-test.o ./main-test.o
TARGET = ../bin/deauth-attack
DTARGET = ../bin/deauth-attack-test
LIBS = -lpcap -pthread

all: $(TARGET)
debug: $(DTARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(@) $(^) $(LIBS)

$(DTARGET): $(DOBJECTS)
	$(CXX) $(DEBUGFLAGS) -o $(@) $(^) $(LIBS)

main.o: ./main.cpp
deauth-attack.o: ./deauth-attack.cpp
mac.o : ./mac.hpp ./mac.cpp

main-test.o: ./main.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
deauth-attack-test.o: ./deauth-attack.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
mac-test.o : ./mac.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)

clean:
	rm -f $(TARGET)
	rm -f *.o

.PHONY: all debug clean
