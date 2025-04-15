#include "security.h"
#include "device.h"
#include <iostream>
#include <stdexcept>
#include <string>
#include <chrono>
#include <thread>
#include <functional>
#include <algorithm>

SecurityModule::SecurityModule(const SecurityConfig& config, Device& device)
    : config_(config), device_(device) {}

bool SecurityModule::checkWriteAccess(uint32_t address, size_t size) {
    return true;
}

bool SecurityModule::checkReadAccess(uint32_t address, size_t size) {
    return true;
}

bool SecurityModule::checkDiskAuthenticity(const std::string& diskId) {
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
    uint64_t writeEnd = static_cast<uint64_t>(address) + size;
    uint32_t bufferStart = bufferAddress_;
    uint64_t bufferEnd = static_cast<uint64_t>(bufferAddress_) + bufferSize_;

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

// --- StackCanarySecurity ---

StackCanarySecurity::StackCanarySecurity(const SecurityConfig& config, Device& device)
    : SecurityModule(config, device), isInitialized_(false) {
    canaryAddress_ = config_.getAddressParameter("canary_address", 0x0);
    
    if (config_.parameters.find("canary_value") != config_.parameters.end()) {
        canaryValue_ = config_.getAddressParameter("canary_value", 0xDEADBEEF);
    } else {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
        canaryValue_ = dis(gen);
    }
    
    std::cout << "Stack Canary Security Initialized:" << std::endl;
    std::cout << "  Canary Address: 0x" << std::hex << canaryAddress_ << std::dec << std::endl;
    std::cout << "  Canary Value: 0x" << std::hex << canaryValue_ << std::dec << std::endl;
    
    initializeCanary();
}

void StackCanarySecurity::initializeCanary() {
    try {
        uint8_t* canaryBytes = reinterpret_cast<uint8_t*>(&canaryValue_);
        for (size_t i = 0; i < sizeof(canaryValue_); ++i) {
            device_.writeMemory(canaryAddress_ + i, canaryBytes[i]);
        }
        isInitialized_ = true;
        std::cout << "Stack canary initialized at 0x" << std::hex << canaryAddress_ << std::dec << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Failed to initialize stack canary: " << e.what() << std::endl;
        isInitialized_ = false;
    }
}

void StackCanarySecurity::checkCanary() {
    if (!isInitialized_) return;
    
    try {
        uint32_t currentValue = 0;
        for (size_t i = 0; i < sizeof(currentValue); ++i) {
            uint8_t byte = device_.readMemory(canaryAddress_ + i);
            currentValue |= (static_cast<uint32_t>(byte) << (8 * i));
        }
        
        if (currentValue != canaryValue_) {
            std::cerr << "SECURITY VIOLATION: Stack canary corrupted!" << std::endl;
            std::cerr << "  Expected: 0x" << std::hex << canaryValue_ << std::dec << std::endl;
            std::cerr << "  Found: 0x" << std::hex << currentValue << std::dec << std::endl;
            throw std::runtime_error("Stack Smashing Detected");
        }
    } catch (const std::runtime_error& e) {
        throw;
    } catch (const std::exception& e) {
        std::cerr << "Error checking stack canary: " << e.what() << std::endl;
    }
}

bool StackCanarySecurity::checkWriteAccess(uint32_t address, size_t size) {
    if (address <= canaryAddress_ && address + size > canaryAddress_) {
        std::cerr << "SECURITY WARNING: Attempt to overwrite stack canary at 0x" 
                 << std::hex << canaryAddress_ << std::dec << std::endl;
        throw std::runtime_error("Attempt to overwrite stack canary");
    }
    
    checkCanary();
    return true;
}

bool StackCanarySecurity::checkReadAccess(uint32_t address, size_t size) {
    if (address <= canaryAddress_ && address + size > canaryAddress_) {
        std::cerr << "SECURITY WARNING: Attempt to read stack canary at 0x" 
                 << std::hex << canaryAddress_ << std::dec << std::endl;
    }
    return true;
}

// --- FakeDiskCheckSecurity ---

FakeDiskCheckSecurity::FakeDiskCheckSecurity(const SecurityConfig& config, Device& device)
    : SecurityModule(config, device) {
    expectedDiskId_ = config_.parameters.find("expected_disk_id") != config_.parameters.end() 
                    ? config_.parameters.at("expected_disk_id") 
                    : "ORIGINAL_DISK";
    
    diskSignature_ = config_.parameters.find("disk_signature") != config_.parameters.end() 
                   ? config_.parameters.at("disk_signature")
                   : "VALID_SIGNATURE";
    
    allowUnauthorized_ = config_.getBoolParameter("allow_unauthorized", false);
    
    std::cout << "Fake Disk Check Security Initialized:" << std::endl;
    std::cout << "  Expected Disk ID: " << expectedDiskId_ << std::endl;
    std::cout << "  Allow Unauthorized: " << (allowUnauthorized_ ? "Yes" : "No") << std::endl;
}

bool FakeDiskCheckSecurity::verifySignature(const std::string& diskId) {
    // Для простоты просто проверяем, совпадает ли ID с ожидаемым
    return diskId == expectedDiskId_;
}

bool FakeDiskCheckSecurity::checkDiskAuthenticity(const std::string& diskId) {
    std::cout << "Checking disk authenticity: ID=" << diskId << std::endl;
    
    bool isAuthentic = verifySignature(diskId);
    
    if (!isAuthentic) {
        std::cout << "Security Check: Disk authenticity verification failed!" << std::endl;
        if (!allowUnauthorized_) {
            std::cout << "Security Action: Preventing unauthorized disk access." << std::endl;
            throw std::runtime_error("Unauthorized disk detected!");
        } else {
            std::cout << "Security Notice: Unauthorized disk detected (allowed)." << std::endl;
        }
    } else {
        std::cout << "Security Check: Disk authenticity verified successfully." << std::endl;
    }
    
    return true;
}

// --- ASLRSecurity ---

ASLRSecurity::ASLRSecurity(const SecurityConfig& config, Device& device)
    : SecurityModule(config, device) {
    std::random_device rd;
    rng_ = std::mt19937(rd());
    
    minOffset_ = config_.getAddressParameter("min_offset", 0x1000);
    maxOffset_ = config_.getAddressParameter("max_offset", 0x10000);
    alignment_ = config_.getAddressParameter("alignment", 0x10);
    enabled_ = config_.getBoolParameter("enabled", true);
    
    std::cout << "ASLR Security Initialized:" << std::endl;
    std::cout << "  Enabled: " << (enabled_ ? "Yes" : "No") << std::endl;
    std::cout << "  Min Offset: 0x" << std::hex << minOffset_ << std::dec << std::endl;
    std::cout << "  Max Offset: 0x" << std::hex << maxOffset_ << std::dec << std::endl;
    std::cout << "  Alignment: 0x" << std::hex << alignment_ << std::dec << std::endl;
}

uint32_t ASLRSecurity::getRandomOffset() {
    if (!enabled_) return 0;
    
    std::uniform_int_distribution<uint32_t> dis(minOffset_ / alignment_, maxOffset_ / alignment_);
    uint32_t offset = dis(rng_) * alignment_;
    
    return offset;
}

uint32_t ASLRSecurity::randomizeLoadAddress(uint32_t originalAddress) {
    if (!enabled_) return originalAddress;
    
    uint32_t offset = getRandomOffset();
    uint32_t randomizedAddress = originalAddress + offset;
    
    std::cout << "ASLR: Randomized load address from 0x" << std::hex << originalAddress 
              << " to 0x" << randomizedAddress << " (offset: 0x" << offset << ")" << std::dec << std::endl;
    
    return randomizedAddress;
}

// --- TimeAttackSecurity ---

TimeAttackSecurity::TimeAttackSecurity(const SecurityConfig& config, Device& device)
    : SecurityModule(config, device) {
    correctPassword_ = config_.parameters.find("correct_password") != config_.parameters.end() 
                     ? config_.parameters.at("correct_password") 
                     : "SECRET_PASSWORD";
    
    vulnerableCheck_ = config_.getBoolParameter("vulnerable_check", true);
    
    std::cout << "Time Attack Security Initialized:" << std::endl;
    std::cout << "  Password Length: " << correctPassword_.length() << " chars" << std::endl;
    std::cout << "  Vulnerable Check: " << (vulnerableCheck_ ? "Yes" : "No") << std::endl;
}

bool TimeAttackSecurity::checkPassword(const std::string& password) {
    if (vulnerableCheck_) {
        std::cout << "Using vulnerable password check (susceptible to timing attacks)" << std::endl;
        
        bool match = true;
        size_t maxLength = std::min(password.length(), correctPassword_.length());
        
        for (size_t i = 0; i < maxLength; ++i) {
            if (password[i] != correctPassword_[i]) {
                match = false;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        
        if (match && password.length() == correctPassword_.length()) {
            std::cout << "Password check: Correct" << std::endl;
            return true;
        } else {
            std::cout << "Password check: Incorrect" << std::endl;
            return false;
        }
    } else {
        std::cout << "Using secure password check (constant time)" << std::endl;
        
        std::this_thread::sleep_for(std::chrono::milliseconds(50 * correctPassword_.length()));
        
        bool match = (password == correctPassword_);
        std::cout << "Password check: " << (match ? "Correct" : "Incorrect") << std::endl;
        return match;
    }
}

// --- Factory function ---

std::unique_ptr<SecurityModule> createSecurityModule(const std::string& type, const SecurityConfig& config, Device& device) {
    if (type == "BufferOverflow") {
        return std::make_unique<BufferOverflowSecurity>(config, device);
    } else if (type == "StackCanary") {
        return std::make_unique<StackCanarySecurity>(config, device);
    } else if (type == "FakeDiskCheck") {
        return std::make_unique<FakeDiskCheckSecurity>(config, device);
    } else if (type == "ASLR") {
        return std::make_unique<ASLRSecurity>(config, device);
    } else if (type == "TimeAttack") {
        return std::make_unique<TimeAttackSecurity>(config, device);
    } else if (type == "None") {
        return std::make_unique<SecurityModule>(config, device);
    } else {
        std::cerr << "Warning: Unknown security module type '" << type << "', using default." << std::endl;
        return std::make_unique<SecurityModule>(config, device);
    }
}