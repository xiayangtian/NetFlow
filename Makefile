include /usr/local/etc/PcapPlusPlus.mk
SOURCE := packetcapturetest.cpp
#SOURCE := readandwritetest.cpp
#SOURCE := tosql.cpp
TARGET := capture
#TARGET := readandwrite
#TARGET := tosql
all:
	g++ $(PCAPPP_INCLUDES) -c -o main.o $(SOURCE) -I/usr/include/mysql -L/usr/lib64/mysql -lmysqlclient
	g++ $(PCAPPP_LIBS_DIR) -o $(TARGET) main.o $(PCAPPP_LIBS) -I/usr/include/mysql -L/usr/lib64/mysql -lmysqlclient
	rm main.o
clean:
	rm capture
	rm readandwrite
	rm tosql
