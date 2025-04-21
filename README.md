# Wemu: The Vulnerable Emulator for Security Challenges

[![Language](https://img.shields.io/badge/language-C%2B%2B-blue.svg)](https://isocpp.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://cmake.org/)
[![Build](https://img.shields.io/badge/build-CMake-orange.svg)](https://cmake.org/)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()
[![Assembler](https://img.shields.io/badge/Assembler-Built--in-informational.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

Wemu is an extensible emulator platform designed for creating and solving low-level security challenges. It allows you to define custom virtual devices with specific CPU architectures, memory layouts, and, crucially, configurable security vulnerabilities or protections.

**Wemu empowers you to:**

1.  **Define Custom Devices:** Specify RAM size, program entry points, and enable/configure various security modules (`.wemu` files).
2.  **Write Low-Level Code:** Develop programs for the emulated CPU using a simple assembly language (`.asm` files).
3.  **Emulate Execution:** Run the defined device and program within a controlled virtual environment.
4.  **Interact and Debug:** Step through code execution, inspect CPU registers and memory, and manipulate the system state via an interactive command line.
5.  **Learn and Experiment:** Explore common vulnerabilities (like buffer overflows, timing attacks) and understand protection mechanisms (like stack canaries, ASLR) in a hands-on manner.

## Core Concepts

Wemu revolves around two primary file types:

*   **Configuration Files (`.wemu`)**: Text files describing the parameters of a specific challenge or emulated system.
    *   **Hardware:** Device type, RAM size.
    *   **Program:** Path to the assembly file (`.asm`) to be loaded and its load address.
    *   **Security:** Which security module(s) are active (e.g., `BufferOverflow`, `StackCanary`) and their specific parameters (buffer addresses, canary values, ASLR offsets, etc.).
    *   **Multiple Modules:** You can enable and configure several security modules simultaneously for complex scenarios.

*   **Assembly Files (`.asm`)**: Text files containing the source code for the emulated Wemu CPU, written using its specific instruction set. Wemu includes a built-in assembler that translates these files into executable bytecode on the fly.

**Relationship:** The `.wemu` file dictates the hardware and security environment and points to the `.asm` file containing the program to be run within that environment.

## Getting Started

### Prerequisites

*   **CMake:** Version 3.10 or higher ([https://cmake.org/download/](https://cmake.org/download/))
*   **C++ Compiler:** A modern C++ compiler supporting C++17 (e.g., GCC, Clang, MSVC).

### Building Wemu

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd Wemu
    ```
2.  **Create a build directory:**
    ```bash
    mkdir build
    cd build
    ```
3.  **Run CMake:**
    ```bash
    # For Makefiles (Linux/macOS)
    cmake ..

    # For Visual Studio (Windows) - Choose the appropriate generator
    cmake .. -G "Visual Studio 17 2022"
    ```
4.  **Build the project:**
    ```bash
    # For Makefiles
    make

    # For Visual Studio (from Developer Command Prompt or using MSBuild)
    msbuild Wemu.sln /property:Configuration=Release # Or Debug
    ```
    The executable (`wemu` or `wemu.exe`) will be located in the `build` or `build/Debug|Release` directory.

### Running Wemu

Execute Wemu from your terminal, providing the path to a `.wemu` configuration file as a command-line argument:

```bash
# From the build directory (Linux/macOS)
./wemu ../configs/buffer_overflow.wemu

# From the build/Debug directory (Windows)
.\Debug\wemu.exe ..\configs\buffer_overflow.wemu
```

Wemu will load the configuration, assemble the specified `.asm` file, initialize the emulated device and security modules, load the bytecode into memory, and drop you into the interactive command prompt.

## Configuration (`.wemu` Files)

Configuration files use a simple `key = value` format. Comments start with `#`.

**Example (`configs/multi_security.wemu`):**

```ini
# --- Device Configuration ---
device.type = SimpleTestCPU   # Currently the only type
device.ramMB = 1              # Allocate 1MB of RAM

# --- Program Configuration ---
program.assembly_file = multi_security.asm # Path relative to .wemu file

# --- Security Modules ---
# Multiple modules can be defined

# Module 0 (Primary, defined by security.type)
security.type = BufferOverflow
security.buffer_address = 0x300
security.buffer_size = 16
security.allow_overflow = true  # Set to false to prevent overflow

# Module 1 (Additional)
security.module_1 = StackCanary
security.canary_address = 0x400
# security.canary_value = 0xDEADBEEF # Optional: Fixed canary value

# Module 2 (Additional)
security.module_2 = ASLR
security.min_offset = 0x1000
security.max_offset = 0x8000
security.alignment = 0x10      # Usually 0x10 or page size
security.enabled = true
```

**Common Parameters:**

*   `device.type`: Specifies the device model (currently `SimpleTestCPU`).
*   `device.ramMB`: Sets the amount of RAM for the emulated device.
*   `program.assembly_file`: Specifies the path to the `.asm` file containing the code to run. Relative paths are resolved based on the `.wemu` file's location.
*   `security.type`: Defines the primary security module. Use `None` for no security.
*   `security.module_X`: Defines additional security modules (where X is a number starting from 1).
*   Module-specific parameters (e.g., `buffer_address`, `canary_address`, `min_offset`) configure the behavior of each security module. See `security_examples.md` for details.

## Assembly Language (`.asm` Files)

Wemu features a simple, custom CPU architecture and a built-in two-pass assembler.

**Syntax:**

*   **Instructions:** `MNEMONIC OPERAND1, OPERAND2, ...`
*   **Operands:** Registers (`R0` to `R7`), immediate values (decimal `100`, hex `0x64`), labels.
*   **Labels:** Define addresses (e.g., `loop_start:`). Used as targets for jumps and calls.
*   **Directives:**
    *   `.ORG <address>`: Specifies the load address for the assembled code (defaults to `0x100` if omitted).
*   **Comments:** Lines starting with `;` are ignored.

**Instruction Set:**

| Mnemonic  | Opcode | Operands                   | Description                                      | Flags Affected |
| :-------- | :----- | :------------------------- | :----------------------------------------------- | :------------- |
| `NOP`     | `0x00` |                            | No operation                                     | -              |
| `LOAD_IMM`| `0x01` | `R<dst>, <imm32>`          | Load 32-bit immediate value into register        | -              |
| `STORE_REG`|`0x02` | `R<src>, <addr32>`         | Store register value to memory address           | -              |
| `LOAD_MEM`| `0x03` | `R<dst>, <addr32>`         | Load value from memory address into register     | -              |
| `ADD`     | `0x10` | `R<dst>, R<src1>, R<src2>` | `R<dst> = R<src1> + R<src2>`                     | ZF, CF         |
| `SUB`     | `0x11` | `R<dst>, R<src1>, R<src2>` | `R<dst> = R<src1> - R<src2>`                     | ZF, CF         |
| `CMP_REG` | `0x12` | `R<src1>, R<src2>`         | Compare `R<src1>` and `R<src2>`                  | ZF, CF         |
| `AND`     | `0x13` | `R<dst>, R<src1>, R<src2>` | Bitwise AND                                      | ZF             |
| `OR`      | `0x14` | `R<dst>, R<src1>, R<src2>` | Bitwise OR                                       | ZF             |
| `XOR`     | `0x15` | `R<dst>, R<src1>, R<src2>` | Bitwise XOR                                      | ZF             |
| `NOT`     | `0x16` | `R<dst>, R<src>`           | Bitwise NOT                                      | ZF             |
| `SHL`     | `0x17` | `R<dst>, R<src>, R<count>` | Shift Left (logical)                             | ZF, CF         |
| `SHR`     | `0x18` | `R<dst>, R<src>, R<count>` | Shift Right (logical)                            | ZF, CF         |
| `SAR`     | `0x19` | `R<dst>, R<src>, R<count>` | Shift Right (arithmetic)                         | ZF, CF         |
| `JMP`     | `0x20` | `<addr32>` / `<label>`     | Unconditional jump                               | -              |
| `JE`      | `0x21` | `<addr32>` / `<label>`     | Jump if Equal (ZF=1)                             | -              |
| `JNE`     | `0x22` | `<addr32>` / `<label>`     | Jump if Not Equal (ZF=0)                         | -              |
| `JG`      | `0x23` | `<addr32>` / `<label>`     | Jump if Greater (unsigned, ZF=0 and CF=0)        | -              |
| `JL`      | `0x24` | `<addr32>` / `<label>`     | Jump if Less (unsigned, CF=1)                    | -              |
| `JGE`     | `0x25` | `<addr32>` / `<label>`     | Jump if Greater or Equal (unsigned, CF=0)        | -              |
| `JLE`     | `0x26` | `<addr32>` / `<label>`     | Jump if Less or Equal (unsigned, ZF=1 or CF=1) | -              |
| `PUSH`    | `0x30` | `R<src>`                   | Push register value onto stack                   | -              |
| `POP`     | `0x31` | `R<dst>`                   | Pop value from stack into register               | -              |
| `CALL`    | `0x32` | `<addr32>` / `<label>`     | Push return address, jump to subroutine          | -              |
| `RET`     | `0x33` |                            | Pop return address, jump                         | -              |
| `HALT`    | `0xFF` |                            | Halt CPU execution                               | -              |

*(Note: 32-bit immediate values and addresses are encoded in Little Endian byte order.)*

## Security Modules

Wemu supports several pluggable security modules:

*   **`BufferOverflowSecurity`**: Monitors memory writes to a specific buffer, optionally preventing or allowing overflows.
*   **`StackCanarySecurity`**: Places a "canary" value on the stack to detect stack buffer overflows that corrupt the return address.
*   **`ASLRSecurity`**: Randomizes the base address where the program code is loaded into memory on each run.
*   **`FakeDiskCheckSecurity`**: Simulates a check for an expected "disk ID" or program signature.
*   **`TimeAttackSecurity`**: Models a timing vulnerability in operations like password checking.

These modules are configured in the `.wemu` file and interact with the CPU during memory access or specific operations. See `security_examples.md` for detailed configuration and exploitation examples.

## Interactive Mode

Once Wemu starts, you interact with it via the command prompt:

*   `step` (or `s`): Execute the single next CPU instruction.
*   `run` (or `r`): Run instructions continuously until `HALT`, an error, or manual interruption (`Ctrl+C`).
*   `regs`: Display the current state of CPU registers (R0-R7, PC, SP, Flags).
*   `read <addr_hex> [count_dec]` (or `rd`): Read and display memory contents starting at `<addr_hex>` (hex) for `[count_dec]` bytes (decimal, default 1, max 64).
*   `write <addr_hex> <byte1_hex> [byte2_hex] ...` (or `wr`): Write one or more bytes (hex) to memory starting at `<addr_hex>` (hex).
*   `quit` (or `q`): Exit the emulator.
*   `help` (or `h`): Show this list of commands.

The prompt shows the current Program Counter (`PC`) and status flags (`ZF`, `CF`).

## Examples

The `configs/` directory contains example `.wemu` and `.asm` files demonstrating each security module:

*   `buffer_overflow.*`
*   `stack_canary.*`
*   `aslr.*`
*   `fake_disk_check.*`
*   `time_attack.*`
*   `multi_security.*` (Combines Buffer Overflow, Stack Canary, and ASLR)

Refer to `security_examples.md` for detailed explanations and step-by-step guides on how to approach and exploit the vulnerabilities configured in these examples using the interactive mode commands.

## Contributing

Contributions are welcome! Feel free to open issues for bugs or feature requests, or submit pull requests.

## License

Wemu is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## Future Development

*   Interrupt handling system.
*   Basic I/O device support.
*   Additional security modules (e.g., DEP/NX, Heap Protection).
*   Enhanced debugging features (disassembler, breakpoints).
*   Potential integration with external analysis tools.
*   Online platform for hosting challenges. 