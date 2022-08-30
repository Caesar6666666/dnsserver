server: main.cpp #client
	sudo clang++ main.cpp -o ./bin/server -O2 -std=c++17 -Wall -g

# client: client.cpp
# 	sudo clang++ client.cpp -o ./bin/client -O2 -std=c++17 -Wall -g

.PHONY:run
run:
	sudo ./bin/server

.PHONY:clean
clean:
	rm -rf ./bin/*