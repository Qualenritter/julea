#CFLAGS  += -fsanitize=address
CFLAGS  += $(shell pkg-config --cflags glib-2.0 julea-object julea-kv julea-db)
#LDFLAGS += -fsanitize=address
LDLIBS  += $(shell pkg-config --libs glib-2.0 julea-object julea-kv julea-db)

CFLAGS += -ggdb -Wall -Wextra

BIN = hello-world hdf5-example benchmark-mpi db-example-with-error-handling db-example benchmark-hdf

all: $(BIN)

benchmark-mpi:
CC=mpicc

benchmark-hdf:
LDLIBS += -lhdf5

db-example-with-error-handling:

db-example:

hello-world:

hdf5-example:
LDLIBS += -lhdf5

clean:
	rm -f $(BIN)

run: $(BIN)
	../scripts/setup.sh start
	./$(BIN)
	../scripts/setup.sh stop
