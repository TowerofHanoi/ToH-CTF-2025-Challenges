CC = gcc

CFLAGS = -no-pie \
		 -Wl,-z,relro

TARGET = vm

SRC = vm.c


.PHONY: all
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)
	@checksec --file=$(TARGET)


clean:
	@echo "Cleaning up build artifacts..."
	rm -f $(TARGET)
