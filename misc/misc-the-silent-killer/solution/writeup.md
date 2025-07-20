# The Hidden Killer

## Description

The challenge consists in a multi-process database, implemented as a forking server with two types of processes:
- **Manager**: A single process managing the file write operations. It receives write transactions from all the workers and applies them to the database. It also offers a CLI interface for read and write operations.
- **Worker**: A process handling a single DB write-only connection. It allows to build insert operations and commit them.

In this system the manager is essential to make the database work, as it is the only process that can write to the database file.
Therefore, to guarantee high-availability, whenever the manager crashes, the first worker to notice the crash will be upgraded to manager.

## Vulnerability

As you probably noticed, there's no need to upgrade a worker considering we're not in a non-distributed environment.
It would be reasonable to create a new manager "from scratch" rather than promoting the worker, which will give high-level prvileges to a low-level connection. Given these premises it's easy to notice that the goal should be to kill the manager.

Furthermore in the worker process there is no limit on the accusations per arrest. This means it is possible to make the worker consume an arbitrary quantity of memory, potentially exhausting the container memory.

## Exploit

The exploit follows the research paper by Bossi, Mammone et al. [1] which exploits the Out-of-Memory killer to indirectly kill "innocent" processes. Since this challenge is hosted in a container with limited RAM and swap, whenever such limit is hit, the host kills the biggest process (highest *badness* score) within the container. This behavior can be abused by filling the container's memory with workers smaller than the manager.


Here are the main steps:
- Commit lots of transactions to fill the manager's cache memory (which is unfortunately capped)
- Create some workers with uncommitted transactions remaining on the worker's cache. Since the number of uncommitted arrests is limited, each arrest should contain a huge amount of accusations. **The workers must be smaller than the manager, but also big enough to trigger the OOM killer**
- The OOM killer will kill the manager :)
- Close active workers to avoid further OOM killer invocations and protect the new manager
- Spawn a new worker and commit a transaction to upgrade it to manager
- Interact with the upgraded worker to read from the database

Here are the main challenges to overcome:
- when committing transactions, the inserted data is cloned by the worker before being sent to the manager, creating a memory spike which might invoke the OOM killer against the worker. To overcome this, when filling the manager's cache, it is important to use serveral transactions with a limited amount of data instead of just one huge transaction.
- tuning the size and the number of requests to obtain the desired memory usage can be tricky. The best way is to try it locally with different values and monitoring the memory usage of each process.

### Flag: 
`toh{N0t_3v3n_7h3_FB1_C4n_5t0p_7h3_00M_K1ll3r}`

### Unintended Behavior
While the manager cache is capped to 64MB, it is actually possible to make the process momentarily allocate much more memory. In fact when a new transaction is committed, the manager will need to parse the json request, indirectly cloning and storing the transaction data in memory before checking if it exceeds the size limit. This behavior can be exploited to reduce the amount of memory required to be consumed by workers, making the attack easier.

### References:

[1] Bossi, L., Mammone, D., Carminati, M., Zanero, S., & Longari, S. (2025). Linux hurt itself in its confusion! Exploiting Out-of-Memory Killer for Confusion Attacks via Heuristic Manipulation. In Detection of Intrusions and Malware, and Vulnerability Assessment (DIMVA) 2025 (pp. N-A).