#ifndef DEVICE_H
#define DEVICE_H

#include "config_loader.h"
#include <vector>
#include <cstdint>
#include <array>

// Предварительное объявление класса
class SecurityModule;

enum Opcode : uint8_t {
    NOP      = 0x00,
    LOAD_IMM = 0x01, 
    STORE_REG= 0x02, 
    LOAD_MEM = 0x03, 
    ADD      = 0x10, 
    SUB      = 0x11, 
    CMP_REG  = 0x12, 
    JMP      = 0x20, 
    JE       = 0x21, 
    JNE      = 0x22, 
    HALT     = 0xFF  
};  

struct CpuState {
    uint32_t pc = 0;
    std::array<uint32_t, 8> registers{}; 
    bool halted = false; 
    bool zeroFlag = false;
    bool carryFlag = false;
   
};

class Device {
public:
    Device(const DeviceConfig& config);
    void processCycle(); 
    uint8_t readMemory(uint32_t address);
    void writeMemory(uint32_t address, uint8_t value);
    bool isHalted() const;
    void loadProgram(const std::vector<uint8_t>& bytecode, uint32_t loadAddress);

    uint32_t getRegister(uint8_t index) const;
    uint32_t getPC() const;
    bool getZeroFlag() const;
    bool getCarryFlag() const;
    const std::array<uint32_t, 8>& getRegisters() const;

    void setSecurityModule(SecurityModule* module);

private:
    friend class SecurityModule;
    void fetchDecodeExecute(); 
    uint16_t read16(uint32_t address); 
    uint32_t read32(uint32_t address); 
    void write32(uint32_t address, uint32_t value);

    DeviceConfig config_;
    std::vector<uint8_t> memory_;
    CpuState cpuState_;
    class SecurityModule* securityModule_ = nullptr;
};

#endif 