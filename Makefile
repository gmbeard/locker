PREFIX ?= "/usr/local"
BIN = "/bin"

install: locker
	install $^ ${PREFIX}${BIN}
