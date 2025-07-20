
CXX=riscv-none-elf-g++
CXXFLAGS=-Wall -std=c++20 -Os -march=rv32ec -mabi=ilp32e -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections -flto -g -I../runtime
LDFLAGS=-nostdlib -Wl,--start-group -lstdc++ -lc -lm -lgcc -Wl,--end-group -Wl,-Map=main.map -T ../runtime/ch32v003.ld -Wl,--gc-sections

OBJ=sound.o ../runtime/runtime.o

all: $(OBJ)
	$(CXX) $(CXXFLAGS) -o main.elf $(OBJ) $(LDFLAGS)
	riscv-none-elf-objcopy -O binary main.elf main.bin
	riscv-none-elf-size main.elf

clean:
	rm -f $(OBJ) main.elf main.bin main.map

program:
	minichlink -w main.bin flash -b
