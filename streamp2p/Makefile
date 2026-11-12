CXX ?= g++
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra -Wpedantic -Wshadow
LDLIBS += -pthread
SRC = $(filter-out src/main.cpp, $(wildcard src/*.cpp))
HDR = $(wildcard src/*.hpp)

all: bin/streamp2p bin/unit_tests

bin/streamp2p: $(SRC) src/main.cpp $(HDR)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -Isrc -o $@ $(SRC) src/main.cpp $(LDLIBS)

bin/unit_tests: $(SRC) tests/unit_tests.cpp $(HDR)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -Isrc -o $@ $(SRC) tests/unit_tests.cpp $(LDLIBS)

test: all
	./bin/unit_tests
	python3 scripts/run_tests.py

fuzz: bin/streamp2p
	python3 scripts/fuzz.py

bin-asan/streamp2p: $(SRC) src/main.cpp $(HDR)
	@mkdir -p bin-asan
	$(CXX) -std=c++20 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Isrc -o $@ $(SRC) src/main.cpp $(LDLIBS)

bin-asan/unit_tests: $(SRC) tests/unit_tests.cpp $(HDR)
	@mkdir -p bin-asan
	$(CXX) -std=c++20 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Isrc -o $@ $(SRC) tests/unit_tests.cpp $(LDLIBS)

bin-tsan/streamp2p: $(SRC) src/main.cpp $(HDR)
	@mkdir -p bin-tsan
	$(CXX) -std=c++20 -O1 -g -fsanitize=thread -Wall -Wextra -Isrc -o $@ $(SRC) src/main.cpp $(LDLIBS)

bin-tsan/unit_tests: $(SRC) tests/unit_tests.cpp $(HDR)
	@mkdir -p bin-tsan
	$(CXX) -std=c++20 -O1 -g -fsanitize=thread -Wall -Wextra -Isrc -o $@ $(SRC) tests/unit_tests.cpp $(LDLIBS)

sanitize: bin-asan/streamp2p bin-asan/unit_tests
	./bin-asan/unit_tests
	STREAMP2P_BIN=bin-asan/streamp2p STREAMP2P_SLOW=3 python3 scripts/run_tests.py
	STREAMP2P_BIN=bin-asan/streamp2p STREAMP2P_SLOW=3 python3 scripts/fuzz.py

tsan: bin-tsan/streamp2p bin-tsan/unit_tests
	TSAN_OPTIONS="halt_on_error=0 second_deadlock_stack=1" ./bin-tsan/unit_tests
	TSAN_OPTIONS="halt_on_error=0 second_deadlock_stack=1" STREAMP2P_BIN=bin-tsan/streamp2p STREAMP2P_SLOW=4 python3 scripts/run_tests.py
	TSAN_OPTIONS="halt_on_error=0 second_deadlock_stack=1" STREAMP2P_BIN=bin-tsan/streamp2p STREAMP2P_SLOW=4 python3 scripts/fuzz.py

clean:
	rm -rf bin bin-asan bin-tsan

.PHONY: all test fuzz sanitize tsan clean
