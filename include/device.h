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
    // Логические операции
    AND      = 0x13,
    OR       = 0x14,
    XOR      = 0x15,
    NOT      = 0x16,
    // Битовые операции
    SHL      = 0x17, // Сдвиг влево
    SHR      = 0x18, // Логический сдвиг вправо
    SAR      = 0x19, // Арифметический сдвиг вправо
    // Операции со стеком
    PUSH     = 0x30,
    POP      = 0x31,
    // Вызовы функций
    CALL     = 0x32,
    RET      = 0x33,
    // Переходы
    JMP      = 0x20, 
    JE       = 0x21, 
    JNE      = 0x22,
    JG       = 0x23, // Переход если больше (not CF and not ZF)
    JL       = 0x24, // Переход если меньше (CF)
    JGE      = 0x25, // Переход если больше или равно (not CF)
    JLE      = 0x26, // Переход если меньше или равно (CF or ZF)
    // Прочие
    HALT     = 0xFF  
};  

struct CpuState {
    uint32_t pc = 0;
    std::array<uint32_t, 8> registers{}; 
    bool halted = false; 
    bool zeroFlag = false;
    bool carryFlag = false;
    uint32_t sp = 0; // Stack Pointer - указатель стека
    uint32_t stackBase = 0; // Базовый адрес стека
    uint32_t stackSize = 0; // Размер стека
};

class Device {
public:
    Device(const DeviceConfig& config);
    void processCycle(); 
    uint8_t readMemory(uint32_t address);
    void writeMemory(uint32_t address, uint8_t value);
    bool isHalted() const;
    void loadProgram(const std::vector<uint8_t>& bytecode, uint32_t loadAddress);

    // Методы для работы со стеком
    void initStack(uint32_t stackBase, uint32_t stackSize);
    void pushToStack(uint32_t value);
    uint32_t popFromStack();

    uint32_t getRegister(uint8_t index) const;
    uint32_t getPC() const;
    bool getZeroFlag() const;
    bool getCarryFlag() const;
    const std::array<uint32_t, 8>& getRegisters() const;
    uint32_t getStackPointer() const;

    void setSecurityModule(SecurityModule* module);
    void addSecurityModule(SecurityModule* module);

private:
    friend class SecurityModule;
    void fetchDecodeExecute(); 
    uint16_t read16(uint32_t address); 
    uint32_t read32(uint32_t address); 
    void write32(uint32_t address, uint32_t value);
    bool checkStackAccess(uint32_t address, size_t size, bool isWrite);

    DeviceConfig config_;
    std::vector<uint8_t> memory_;
    CpuState cpuState_;
    // Поддержка нескольких модулей безопасности
    std::vector<SecurityModule*> securityModules_;
};

#endif 