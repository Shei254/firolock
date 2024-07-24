CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LIBS = -lssl -lcrypto

TARGET = firolock
PRODUCTION = firolock_x64.run

all: $(TARGET)
install:
	cp $(TARGET) /usr/bin
uninstall:
	rm /usr/bin/$(TARGET)

$(TARGET): main.o
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

main.o: main.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f $(TARGET) *.o
