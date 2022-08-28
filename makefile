server:
	clang++ main.cpp -o ./bin/server -O2 -std=c++17 -Wall -g

client.cpp:
	clang++ client.cpp -o ./bin/client -O2 -std=c++17 -Wall -g

server:
	./bin/server

client:
	./bin/client bilibili.com

clean:
	rm -rf ./bin/*