#ifndef SECURITY_H
#define SECURITY_H

#include "config_loader.h"
// #include "device.h"
#include <memory>
#include <vector>
#include <random>
#include <ctime>

// Предварительное объявление класса
class Device;

class SecurityModule {
public:
    SecurityModule(const SecurityConfig& config, Device& device);
    virtual ~SecurityModule() = default;

    virtual bool checkWriteAccess(uint32_t address, size_t size);
    virtual bool checkReadAccess(uint32_t address, size_t size);
    virtual bool checkDiskAuthenticity(const std::string& diskId = "");
    virtual std::string getName() const { return "Base"; }

protected:
    SecurityConfig config_;
    Device& device_;
};

// Модуль для защиты от переполнения буфера
class BufferOverflowSecurity : public SecurityModule {
public:
    BufferOverflowSecurity(const SecurityConfig& config, Device& device);
    bool checkWriteAccess(uint32_t address, size_t size) override;
    std::string getName() const override { return "BufferOverflow"; }

private:
    uint32_t bufferAddress_;
    size_t bufferSize_;
    bool allowOverflow_;
};

// Модуль для защиты стека с помощью канареек
class StackCanarySecurity : public SecurityModule {
public:
    StackCanarySecurity(const SecurityConfig& config, Device& device);
    bool checkWriteAccess(uint32_t address, size_t size) override;
    bool checkReadAccess(uint32_t address, size_t size) override;
    std::string getName() const override { return "StackCanary"; }

private:
    void initializeCanary();
    void checkCanary();
    
    uint32_t canaryValue_;
    uint32_t canaryAddress_;
    bool isInitialized_;
};

// Модуль для проверки подлинности "диска"
class FakeDiskCheckSecurity : public SecurityModule {
public:
    FakeDiskCheckSecurity(const SecurityConfig& config, Device& device);
    bool checkDiskAuthenticity(const std::string& diskId = "") override;
    std::string getName() const override { return "FakeDiskCheck"; }

private:
    bool verifySignature(const std::string& diskId);
    
    std::string expectedDiskId_;
    std::string diskSignature_;
    bool allowUnauthorized_;
};

// Модуль для рандомизации адресного пространства программы (ASLR)
class ASLRSecurity : public SecurityModule {
public:
    ASLRSecurity(const SecurityConfig& config, Device& device);
    uint32_t randomizeLoadAddress(uint32_t originalAddress);
    std::string getName() const override { return "ASLR"; }

private:
    uint32_t getRandomOffset();
    
    std::mt19937 rng_;
    uint32_t minOffset_;
    uint32_t maxOffset_;
    uint32_t alignment_;
    bool enabled_;
};

// Модуль для моделирования атак по времени
class TimeAttackSecurity : public SecurityModule {
public:
    TimeAttackSecurity(const SecurityConfig& config, Device& device);
    bool checkPassword(const std::string& password);
    std::string getName() const override { return "TimeAttack"; }

private:
    std::string correctPassword_;
    bool vulnerableCheck_;
};

std::unique_ptr<SecurityModule> createSecurityModule(const std::string& type, const SecurityConfig& config, Device& device);

#endif