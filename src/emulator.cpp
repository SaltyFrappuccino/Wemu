#include "emulator.h"
#include <iostream>
#include <stdexcept>
#include <chrono> 
#include <thread> 
#include <filesystem>
#include "security.h" 
#include <limits> 
#include <vector>

Emulator::Emulator(const EmulatorConfig& config)
    : config_(config), device_(config.deviceConfig) {
    std::cout << "Initializing Wemu Emulator..." << std::endl;
    std::cout << "Device Type: " << config_.deviceConfig.deviceType << std::endl;
    std::cout << "RAM: " << config_.deviceConfig.ramSizeMB << " MB" << std::endl;

    securityModule_ = createSecurityModule(config_.securityConfig, device_);
    if (securityModule_ && config_.securityConfig.type != "None") {
        device_.securityModule_ = securityModule_.get();
        std::cout << "Security Module Type: " << config_.securityConfig.type << " initialized." << std::endl;
    } else {
        std::cout << "No security features enabled." << std::endl;
    }

    if (!config_.programFilePath.empty()) {
        try {
            std::filesystem::path programPath = config_.programFilePath;
            std::string finalProgramPath;

            if (programPath.is_relative()) {
                finalProgramPath = (std::filesystem::path(config_.configFileDir) / programPath).string();
                std::cout << "Program path is relative. Resolved path: " << finalProgramPath << std::endl;
            } else {
                finalProgramPath = config_.programFilePath;
                 std::cout << "Program path is absolute: " << finalProgramPath << std::endl;
            }

            device_.loadProgram(finalProgramPath, config_.programLoadAddress);
        } catch (const std::exception& e) {
            std::cerr << "Error loading program: " << e.what() << std::endl;
            throw;
        }
    } else {
        std::cout << "No program file specified in config. Starting with empty memory." << std::endl;
    }
}

void Emulator::run() {
    std::cout << "Running Wemu Emulation... (Type 'help' for commands)" << std::endl;
    std::string line;
    bool autoRun = false;

    while (true) {
        if (device_.isHalted()) {
             std::cout << "CPU Halted." << std::endl;
             autoRun = false;
        }

        std::cout << std::hex << "PC=0x" << device_.getPC()
                  << " ZF=" << device_.getZeroFlag() << " CF=" << device_.getCarryFlag()
                  << std::dec << " > ";

        if (autoRun) {
            try {
                device_.processCycle();
            } catch (const std::exception& e) {
                 std::cerr << "\nRuntime Error: " << e.what() << std::endl;
                 autoRun = false;
            }
            continue;
        }

        if (!std::getline(std::cin, line)) {
            break;
        }

        std::stringstream ss(line);
        std::string command;
        ss >> command;

        try {
            if (command == "step" || command == "s") {
                if (!device_.isHalted()) {
                    device_.processCycle();
                } else {
                     std::cout << "CPU is halted." << std::endl;
                }
            } else if (command == "run" || command == "r") {
                 std::cout << "Entering auto-run mode. Press Ctrl+C to stop." << std::endl;
                autoRun = true;
            } else if (command == "quit" || command == "q") {
                break;
            } else if (command == "regs") {
                 const auto& regs = device_.getRegisters();
                 for(size_t i = 0; i < regs.size(); ++i) {
                     std::cout << "R" << i << " = 0x" << std::hex << regs[i] << std::dec << std::endl;
                 }
             } else if (command == "read" || command == "rd") {
                uint32_t address;
                uint32_t count = 1;
                std::string addrStr, countStr;
                ss >> addrStr >> countStr;

                if (addrStr.empty()) {
                     std::cout << "Usage: read <address_hex> [count_dec]" << std::endl; continue;
                }
                address = std::stoul(addrStr, nullptr, 16);
                if (!countStr.empty()) {
                    count = std::stoul(countStr);
                }
                if (count == 0) count = 1;
                if (count > 64) count = 64; 

                 std::cout << "Reading " << count << " byte(s) from 0x" << std::hex << address << ":" << std::endl;
                for (uint32_t i = 0; i < count; ++i) {
                    uint8_t val = device_.readMemory(address + i);
                    if (i % 16 == 0 && i != 0) std::cout << std::endl;
                     std::cout << " " << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(val);
                }
                std::cout << std::dec << std::endl;

            } else if (command == "write" || command == "wr") {
                uint32_t address;
                std::string addrStr;
                std::vector<uint8_t> values;
                std::string byteStr;
                ss >> addrStr;
                 if (addrStr.empty()) {
                     std::cout << "Usage: write <address_hex> <byte1_hex> [byte2_hex] ..." << std::endl; continue;
                }
                address = std::stoul(addrStr, nullptr, 16);
                while(ss >> byteStr) {
                     values.push_back(static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16)));
                }
                if (values.empty()) {
                    std::cout << "No values provided to write." << std::endl; continue;
                }

                 std::cout << "Writing " << values.size() << " byte(s) to 0x" << std::hex << address << "..." << std::dec << std::endl;
                for(size_t i = 0; i < values.size(); ++i) {
                    device_.writeMemory(address + i, values[i]);
                }

             } else if (command == "help" || command == "h") {
                 std::cout << "Available commands:\n"
                          << "  step (s): Execute one CPU instruction\n"
                          << "  run (r): Run continuously until HALT or error (Ctrl+C to stop)\n"
                          << "  regs: Show CPU registers\n"
                          << "  read (rd) <addr_hex> [count_dec]: Read memory (max 64 bytes)\n"
                          << "  write (wr) <addr_hex> <byte1_hex> ...: Write memory\n"
                          << "  quit (q): Exit emulator\n"
                          << "  help (h): Show this help message" << std::endl;
            } else if (!command.empty()) {
                 std::cout << "Unknown command: " << command << ". Type 'help' for list." << std::endl;
            }
        } catch (const std::exception& e) {
             std::cerr << "\nCommand Error: " << e.what() << std::endl;
        }
    }

    std::cout << "\nWemu simulation finished." << std::endl;
} 