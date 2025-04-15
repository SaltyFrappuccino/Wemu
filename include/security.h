#ifndef SECURITY_H
#define SECURITY_H

#include "config_loader.h"
// #include "device.h"
#include <memory>

// Предварительное объявление класса
class Device;

class SecurityModule {
public:
    SecurityModule(const SecurityConfig& config, Device& device);
    virtual ~SecurityModule() = default;

    virtual bool checkWriteAccess(uint32_t address, size_t size);
    virtual bool checkReadAccess(uint32_t address, size_t size);
    virtual bool checkDiskAuthenticity(/* параметры диска */);

protected:
    SecurityConfig config_;
    Device& device_;
};

class BufferOverflowSecurity : public SecurityModule {
public:
    BufferOverflowSecurity(const SecurityConfig& config, Device& device);
    bool checkWriteAccess(uint32_t address, size_t size) override;

private:
    uint32_t bufferAddress_;
    size_t bufferSize_;
    bool allowOverflow_;
};

// Можно добавить другие классы для FakeDiskCheck и т.д.

std::unique_ptr<SecurityModule> createSecurityModule(const SecurityConfig& config, Device& device);

#endif