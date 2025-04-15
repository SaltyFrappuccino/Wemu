#ifndef EMULATOR_H
#define EMULATOR_H

#include "config_loader.h"
#include "device.h"
#include <memory>

class Emulator {
public:
    Emulator(const EmulatorConfig& config);
    void run();

private:
    EmulatorConfig config_;
    Device device_;
    std::unique_ptr<class SecurityModule> securityModule_;
};

#endif 