#CFLAGS  += -fsanitize=address
#LDFLAGS += -fsanitize=address

CFLAGS  += -ggdb -Wall -Wextra

BIN = hello-world hdf5-example benchmark-mpi

all: $(BIN)

benchmark-mpi:
CC=mpicc
CFLAGS  += $(shell PKG_CONFIG_PATH=../prefix-gcc-benchmark/lib/pkgconfig:$(PKG_CONFIG_PATH) pkg-config --cflags julea-db)
LDLIBS  += $(shell PKG_CONFIG_PATH=../prefix-gcc-benchmark/lib/pkgconfig:$(PKG_CONFIG_PATH) pkg-config --libs julea-db)
CFLAGS  += $(shell PKG_CONFIG_PATH=../prefix-gcc-benchmark/lib/pkgconfig:$(PKG_CONFIG_PATH) pkg-config --cflags glib-2.0)
LDLIBS  += $(shell PKG_CONFIG_PATH=../prefix-gcc-benchmark/lib/pkgconfig:$(PKG_CONFIG_PATH) pkg-config --libs glib-2.0)

hello-world:
CFLAGS  += $(shell PKG_CONFIG_PATH=../prefix-gcc-benchmark/lib/pkgconfig:$(PKG_CONFIG_PATH) pkg-config --cflags julea-object)
LDLIBS  += $(shell PKG_CONFIG_PATH=../prefix-gcc-benchmark/lib/pkgconfig:$(PKG_CONFIG_PATH) pkg-config --libs julea-object)

hdf5-example:
LDLIBS += -lhdf5

clean:
	rm -f $(BIN)

run: $(BIN)
	../scripts/setup.sh start
	./$(BIN)
	../scripts/setup.sh stop
