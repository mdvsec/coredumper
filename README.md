# coredumper
`coredumper` is a tool for dumping process memory into the GDB core format, designed for Linux aarch64 systems. Compared to `gcore`, `coredumper` dumps all readable memory regions, not just the memory regions accessible by the default core dumping mechanism.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/mdvsec/coredumper.git
   cd coredumper
   ```
2. Create a build directory
   ```bash
   mkdir build
   cd build
   ```
3. To build in **Release** mode (default)
   ```bash
   cmake ..
   make
   ```
4. To build in **Debug** mode
   ```bash
   cmake -DCMAKE_BUILD_TYPE=Debug ..
   make
   ```

## Usage
To dump a process core:
```bash
sudo ./coredumper -p <pid> [-o <filename>]
```
Where:
- `-p <pid>`: Specifies the process ID to dump
- `-o <filename>` (optional): Specifies the output filename for the core dump. If not provided, a default filename will be used (\<pid\>_coredump)

## Example
To dump a running `sleep` process and save the core dump as `core_dump`:
```bash
# Start a background process
sleep 5m &

# Get its PID
pid=$!

# Dump process memory
sudo ./coredumper -p $pid -o core_dump

# Analyze the dump with GDB
sudo gdb /bin/sleep -c core_dump
```
