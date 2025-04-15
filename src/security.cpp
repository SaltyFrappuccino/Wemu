#include "security.h"
#include <iostream>
#include <stdexcept>
#include <string>

SecurityModule::SecurityModule(const SecurityConfig& config, Device& device)
    : config_(config), device_(device) {}

bool SecurityModule::checkWriteAccess(uint32_t address, size_t size) {
    return true;
}

bool SecurityModule::checkReadAccess(uint32_t address, size_t size) {
    return true;
}

bool SecurityModule::checkDiskAuthenticity(/* параметры диска */) {
    std::cout << "SecurityModule: Default disk check (always authentic)." << std::endl;
    return true;
}


// --- BufferOverflowSecurity --- 

BufferOverflowSecurity::BufferOverflowSecurity(const SecurityConfig& config, Device& device)
    : SecurityModule(config, device) {
    bufferAddress_ = config_.getAddressParameter("buffer_address", 0x0); 
    bufferSize_ = config_.getParameter<size_t>("buffer_size", 0);       
    allowOverflow_ = config_.getBoolParameter("allow_overflow", false);  

    if (bufferSize_ == 0) {
         std::cerr << "Warning: BufferOverflow security enabled, but buffer_size is 0 or invalid. Disabling check." << std::endl;
         bufferSize_ = 0; 
    }

     std::cout << "BufferOverflow Security Initialized:" << std::endl;
     std::cout << "  Buffer Address: 0x" << std::hex << bufferAddress_ << std::dec << std::endl;
     std::cout << "  Buffer Size: " << bufferSize_ << " bytes" << std::endl;
     std::cout << "  Allow Overflow: " << (allowOverflow_ ? "Yes" : "No") << std::endl;
}

bool BufferOverflowSecurity::checkWriteAccess(uint32_t address, size_t size) {
    if (bufferSize_ == 0) return true; 

    uint32_t writeStart = address;
    uint32_t writeEnd = address + size; 
    uint32_t bufferStart = bufferAddress_;
    uint32_t bufferEnd = bufferAddress_ + bufferSize_; 

    bool overflows = (writeEnd > bufferEnd);

    if (overflows) {
         std::cout << "Security Check: Write attempt [0x" << std::hex << writeStart << " - 0x" << writeEnd << ")"
                  << " overflows buffer [0x" << bufferStart << " - 0x" << bufferEnd << ")!" << std::dec << std::endl;
        if (!allowOverflow_) {
            std::cout << "Security Action: Preventing write." << std::endl;
             throw std::runtime_error("Buffer Overflow prevented!"); 
        } else {
            std::cout << "Security Notice: Buffer Overflow occurred (allowed)." << std::endl;
        }
    }
    return true;
}

std::unique_ptr<SecurityModule> createSecurityModule(const SecurityConfig& config, Device& device) {
    if (config.type == "BufferOverflow") {
        return std::make_unique<BufferOverflowSecurity>(config, device);
    } 
    // TODO: Здесь нужно будет добавить создание других модулей безопасности (FakeDiskCheck и т.д.), когда они появятся.
    else {
        return std::make_unique<SecurityModule>(config, device);
    }
}