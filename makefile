1:
	clang++ main.cpp -o ./bin/dnsserver -O2 -std=c++17 -Wall -g

2:
	clang++ main.cpp -o ./bin/client -O2 -std=c++17 -Wall -g

server:
	./bin/dnsserver

client:
	./bin/client bilibili.com

clean:
	rm -rf ./bin/*