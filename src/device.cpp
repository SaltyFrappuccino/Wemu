#include "device.h"
#include <stdexcept>
#include <iostream>
#include <iomanip> 
#include <fstream>
#include <limits> 
// Helper function to check register index
inline bool isValidRegister(uint8_t reg_idx) {
    return reg_idx < 8;
}

inline void updateFlags(CpuState& state, uint32_t result, uint64_t fullResult) {
    state.zeroFlag = (result == 0);
    state.carryFlag = (fullResult > std::numeric_limits<uint32_t>::max());
    // TODO: Неплохо бы еще реализовать флаги Negative и Overflow.
}

inline void updateFlagsCMP(CpuState& state, uint32_t val1, uint32_t val2) {
    state.zeroFlag = (val1 == val2);
    state.carryFlag = (val1 < val2);
    // TODO: И здесь тоже не помешали бы флаги Negative и Overflow.
}

Device::Device(const DeviceConfig& config)
    : config_(config) {
    std::cout << "Initializing Device: " << config_.deviceType << std::endl;
    // Размер памяти = ramSizeMB * 1024 * 1024 байт
    size_t memoryBytes = static_cast<size_t>(config_.ramSizeMB) * 1024 * 1024;
    try {
        memory_.resize(memoryBytes, 0);
         std::cout << "Allocated " << memoryBytes << " bytes of memory." << std::endl;
    } catch (const std::bad_alloc& /*e*/) {
        throw std::runtime_error("Failed to allocate device memory.");
    }
    // Инициализация других компонентов устройства (CPU, регистры и т.д.)
}

uint16_t Device::read16(uint32_t address) {
    if (address + 1 >= memory_.size()) {
        throw std::runtime_error("Memory read out of bounds (16-bit)");
    }
    return static_cast<uint16_t>(memory_[address]) |
           (static_cast<uint16_t>(memory_[address + 1]) << 8);
}

uint32_t Device::read32(uint32_t address) {
    if (address + 3 >= memory_.size()) {
        throw std::runtime_error("Memory read out of bounds (32-bit)");
    }
    return static_cast<uint32_t>(memory_[address]) |
           (static_cast<uint32_t>(memory_[address + 1]) << 8) |
           (static_cast<uint32_t>(memory_[address + 2]) << 16) |
           (static_cast<uint32_t>(memory_[address + 3]) << 24);
}

void Device::write32(uint32_t address, uint32_t value) {
     if (address + 3 >= memory_.size()) {
        // Проверка безопасности ПЕРЕД фактической записью (даже если out of bounds)
        if (securityModule_) {
            securityModule_->checkWriteAccess(address, 4);
        }
        throw std::runtime_error("Memory write out of bounds (32-bit)");
    }
    if (securityModule_) {
        securityModule_->checkWriteAccess(address, 4);
    }
    memory_[address]     = static_cast<uint8_t>(value & 0xFF);
    memory_[address + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    memory_[address + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    memory_[address + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

void Device::fetchDecodeExecute() {
    if (cpuState_.halted) return;

    if (cpuState_.pc >= memory_.size()) {
        std::cerr << "Error: Program Counter out of bounds! PC=0x" << std::hex << cpuState_.pc << std::dec << std::endl;
        cpuState_.halted = true;
        return;
    }

    // 1. Fetch Opcode
    Opcode opcode = static_cast<Opcode>(readMemory(cpuState_.pc));
    uint32_t currentPC = cpuState_.pc;
    uint32_t nextPC = currentPC + 1; // По умолчанию инкремент на 1 (для опкода)

    try {
        // 2. Decode & Execute
        switch (opcode) {
            case NOP: {
                std::cout << std::hex << "[0x" << currentPC << "] NOP" << std::dec << std::endl;
                break;
            }
            case HALT: {
                std::cout << std::hex << "[0x" << currentPC << "] HALT" << std::dec << std::endl;
                cpuState_.halted = true;
                break;
            }
            case LOAD_IMM: { // 0x01 reg_idx value(4b)
                uint8_t reg_idx = readMemory(currentPC + 1);
                uint32_t value = read32(currentPC + 2);
                if (!isValidRegister(reg_idx)) {
                     throw std::runtime_error("LOAD_IMM: Invalid register index");
                }
                cpuState_.registers[reg_idx] = value;
                std::cout << std::hex << "[0x" << currentPC << "] LOAD_IMM R" << static_cast<int>(reg_idx)
                          << ", 0x" << value << std::dec << std::endl;
                nextPC = currentPC + 1 + 1 + 4; // opcode + reg_idx + value
                break;
            }
             case STORE_REG: { // 0x02 reg_idx address(4b)
                uint8_t reg_idx = readMemory(currentPC + 1);
                uint32_t address = read32(currentPC + 2);
                 if (!isValidRegister(reg_idx)) {
                     throw std::runtime_error("STORE_REG: Invalid register index");
                }
                uint32_t value = cpuState_.registers[reg_idx];
                write32(address, value);
                std::cout << std::hex << "[0x" << currentPC << "] STORE_REG R" << static_cast<int>(reg_idx)
                          << ", [0x" << address << "]" << std::dec << std::endl;
                nextPC = currentPC + 1 + 1 + 4; // opcode + reg_idx + address
                break;
            }
            case LOAD_MEM: { // 0x03 reg_idx address(4b)
                uint8_t reg_idx = readMemory(currentPC + 1);
                uint32_t address = read32(currentPC + 2);
                if (!isValidRegister(reg_idx)) {
                     throw std::runtime_error("LOAD_MEM: Invalid register index");
                }
                uint32_t value = read32(address);
                cpuState_.registers[reg_idx] = value;
                 std::cout << std::hex << "[0x" << currentPC << "] LOAD_MEM R" << static_cast<int>(reg_idx)
                          << ", [0x" << address << "]" << std::dec << std::endl;
                nextPC = currentPC + 1 + 1 + 4; // opcode + reg_idx + address
                break;
            }
            case ADD: { // 0x10 dest src1 src2
                uint8_t dest_reg = readMemory(currentPC + 1);
                uint8_t src1_reg = readMemory(currentPC + 2);
                uint8_t src2_reg = readMemory(currentPC + 3);
                if (!isValidRegister(dest_reg) || !isValidRegister(src1_reg) || !isValidRegister(src2_reg)) {
                    throw std::runtime_error("ADD: Invalid register index");
                }
                uint64_t val1 = cpuState_.registers[src1_reg];
                uint64_t val2 = cpuState_.registers[src2_reg];
                uint64_t result64 = val1 + val2;
                uint32_t result32 = static_cast<uint32_t>(result64);
                cpuState_.registers[dest_reg] = result32;
                updateFlags(cpuState_, result32, result64);
                std::cout << std::hex << "[0x" << currentPC << "] ADD R" << (int)dest_reg
                          << ", R" << (int)src1_reg << ", R" << (int)src2_reg << std::dec << std::endl;
                nextPC = currentPC + 4; // opcode + 3 regs
                break;
            }
            case SUB: { // 0x11 dest src1 src2
                uint8_t dest_reg = readMemory(currentPC + 1);
                uint8_t src1_reg = readMemory(currentPC + 2);
                uint8_t src2_reg = readMemory(currentPC + 3);
                 if (!isValidRegister(dest_reg) || !isValidRegister(src1_reg) || !isValidRegister(src2_reg)) {
                    throw std::runtime_error("SUB: Invalid register index");
                }
                uint32_t val1 = cpuState_.registers[src1_reg];
                uint32_t val2 = cpuState_.registers[src2_reg];
                uint64_t result64 = static_cast<uint64_t>(val1) - static_cast<uint64_t>(val2);
                uint32_t result32 = static_cast<uint32_t>(result64);
                cpuState_.registers[dest_reg] = result32;
                cpuState_.zeroFlag = (result32 == 0);
                cpuState_.carryFlag = (val1 < val2);
                 std::cout << std::hex << "[0x" << currentPC << "] SUB R" << (int)dest_reg
                          << ", R" << (int)src1_reg << ", R" << (int)src2_reg << std::dec << std::endl;
                nextPC = currentPC + 4; // opcode + 3 regs
                break;
            }
            case CMP_REG: { // 0x12 src1 src2
                uint8_t src1_reg = readMemory(currentPC + 1);
                uint8_t src2_reg = readMemory(currentPC + 2);
                if (!isValidRegister(src1_reg) || !isValidRegister(src2_reg)) {
                    throw std::runtime_error("CMP_REG: Invalid register index");
                }
                uint32_t val1 = cpuState_.registers[src1_reg];
                uint32_t val2 = cpuState_.registers[src2_reg];
                updateFlagsCMP(cpuState_, val1, val2);
                std::cout << std::hex << "[0x" << currentPC << "] CMP R" << (int)src1_reg
                          << ", R" << (int)src2_reg << " (ZF=" << cpuState_.zeroFlag << ", CF=" << cpuState_.carryFlag << ")" << std::dec << std::endl;
                nextPC = currentPC + 3; // opcode + 2 regs
                break;
            }
            case JMP: { // 0x20 address(4b)
                uint32_t address = read32(currentPC + 1);
                std::cout << std::hex << "[0x" << currentPC << "] JMP 0x" << address << std::dec << std::endl;
                nextPC = address; 
                break;
            }
             case JE: { // 0x21 address(4b)
                uint32_t address = read32(currentPC + 1);
                 std::cout << std::hex << "[0x" << currentPC << "] JE 0x" << address << std::dec;
                if (cpuState_.zeroFlag) {
                    std::cout << " (Taken)" << std::endl;
                    nextPC = address;
                } else {
                     std::cout << " (Not Taken)" << std::endl;
                    nextPC = currentPC + 1 + 4; // opcode + address
                }
                break;
            }
            case JNE: { // 0x22 address(4b)
                uint32_t address = read32(currentPC + 1);
                std::cout << std::hex << "[0x" << currentPC << "] JNE 0x" << address << std::dec;
                 if (!cpuState_.zeroFlag) {
                     std::cout << " (Taken)" << std::endl;
                    nextPC = address;
                } else {
                    std::cout << " (Not Taken)" << std::endl;
                    nextPC = currentPC + 1 + 4; // opcode + address
                }
                break;
            }
            default: {
                std::cerr << std::hex << "[0x" << currentPC << "] Error: Unknown opcode 0x"
                          << static_cast<int>(opcode) << std::dec << std::endl;
                cpuState_.halted = true;
                break;
            }
        }

        if (!cpuState_.halted) {
            cpuState_.pc = nextPC;
        }

    } catch (const std::runtime_error& e) {
         std::cerr << std::hex << "[0x" << currentPC << "] Runtime Error: " << e.what() << std::dec << std::endl;
         cpuState_.halted = true; /
    }
}

void Device::processCycle() {
    if (cpuState_.halted) return;

    // Заглушка: Моделирование одного такта работы
    // std::cout << "Device cycle processed." << std::endl;
    // Здесь будет логика выполнения инструкций CPU,
    fetchDecodeExecute(); // Выполняем один цикл CPU
    // обновления состояния периферии и т.д.
}

uint8_t Device::readMemory(uint32_t address) {
    if (address >= memory_.size()) {
        std::cerr << "Warning: Memory read out of bounds at address 0x" << std::hex << address << std::dec << std::endl;
        // Можно бросить исключение или вернуть какое-то значение по умолчанию
        // В контексте security challenge, это может быть точкой входа для атаки
        return 0; 
    }
    return memory_[address];
}

void Device::writeMemory(uint32_t address, uint8_t value) {
    if (address >= memory_.size()) {
         // Проверка безопасности ПЕРЕД фактической записью (даже если out of bounds)
        if (securityModule_) {
            securityModule_->checkWriteAccess(address, 1);
        }
          std::cerr << "Warning: Memory write out of bounds at address 0x" << std::hex << address << std::dec << std::endl;
         // Может быть использовано для buffer overflow
         return;
    }
    if (securityModule_) {
        securityModule_->checkWriteAccess(address, 1);
    }
    memory_[address] = value;
}

bool Device::isHalted() const {
    return cpuState_.halted;
}

void Device::loadProgram(const std::vector<uint8_t>& bytecode, uint32_t loadAddress) {

    std::cout << "Loading program bytecode at address 0x" << std::hex << loadAddress << std::dec << "..." << std::endl;

    size_t codeSize = bytecode.size();
    if (loadAddress + codeSize > memory_.size()) {
        throw std::runtime_error("Program bytecode too large for available memory.");
    }

    std::copy(bytecode.begin(), bytecode.end(), memory_.begin() + loadAddress);

    cpuState_.pc = loadAddress;
    cpuState_.halted = false;
    cpuState_.zeroFlag = false;
    cpuState_.carryFlag = false;

    std::cout << "Program loaded. Size: " << codeSize << " bytes. PC set to 0x" << std::hex << cpuState_.pc << std::dec << std::endl;
}

// --- Getters for Debugging/Interaction ---

uint32_t Device::getRegister(uint8_t index) const {
    if (!isValidRegister(index)) {
        throw std::out_of_range("Invalid register index");
    }
    return cpuState_.registers[index];
}

uint32_t Device::getPC() const {
    return cpuState_.pc;
}

bool Device::getZeroFlag() const {
    return cpuState_.zeroFlag;
}

bool Device::getCarryFlag() const {
    return cpuState_.carryFlag;
}

const std::array<uint32_t, 8>& Device::getRegisters() const {
    return cpuState_.registers;
} 