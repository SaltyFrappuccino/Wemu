#ifndef EMULATOR_H
#define EMULATOR_H

#include "config_loader.h"
#include "device.h"
#include "assembler.h"
#include "security.h"
#include <memory>
#include <vector>

class Emulator {
public:
    Emulator(const EmulatorConfig& config);
    void run();

private:
    void initSecurityModules();
    
    EmulatorConfig config_;
    Device device_;
    std::vector<std::unique_ptr<SecurityModule>> securityModules_;
    std::unique_ptr<class Assembler> assembler_;
};

#endif 