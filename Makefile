.PHONY: clean build

all: clean build

build:
	rm -r -f ./docs
	mkdir docs -p
	$(MAKE) -C hbl
clean:
	$(MAKE) -C hbl clean