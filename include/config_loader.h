#ifndef CONFIG_LOADER_H
#define CONFIG_LOADER_H

#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <iostream>
#include <algorithm>

struct DeviceConfig {
    std::string deviceType = "Generic";
    int ramSizeMB = 64;
    std::map<std::string, std::string> parameters;
};

struct SecurityConfig {
    std::string type = "None";
    std::map<std::string, std::string> parameters;

    template<typename T>
    T getParameter(const std::string& key, T defaultValue) const {
        auto it = parameters.find(key);
        if (it == parameters.end()) {
            return defaultValue;
        }
        T value;
        std::stringstream ss(it->second);
        if (!(ss >> value)) {
             std::cerr << "Warning: Could not parse security parameter '" << key << "' with value '" << it->second << "'. Using default." << std::endl;
             return defaultValue;
        }
        return value;
    }

    uint32_t getAddressParameter(const std::string& key, uint32_t defaultValue) const {
         auto it = parameters.find(key);
        if (it == parameters.end()) {
            return defaultValue;
        }
        try {
            if (it->second.size() > 2 && it->second.substr(0, 2) == "0x") {
                return std::stoul(it->second.substr(2), nullptr, 16);
            } else {
                return std::stoul(it->second);
            }
        } catch (...) {
            std::cerr << "Warning: Could not parse security address parameter '" << key << "' with value '" << it->second << "'. Using default." << std::endl;
            return defaultValue;
        }
    }

     bool getBoolParameter(const std::string& key, bool defaultValue) const {
        auto it = parameters.find(key);
        if (it == parameters.end()) {
            return defaultValue;
        }
        std::string lowerVal = it->second;
        std::transform(lowerVal.begin(), lowerVal.end(), lowerVal.begin(), ::tolower);
        if (lowerVal == "true" || lowerVal == "1" || lowerVal == "yes") {
            return true;
        } else if (lowerVal == "false" || lowerVal == "0" || lowerVal == "no") {
            return false;
        } else {
            std::cerr << "Warning: Could not parse security boolean parameter '" << key << "' with value '" << it->second << "'. Using default." << std::endl;
            return defaultValue;
        }
    }
};

struct EmulatorConfig {
    DeviceConfig deviceConfig;
    SecurityConfig securityConfig;
    std::string assemblyFilePath;
    std::string configFileDir;
};

class ConfigLoader {
public:
    EmulatorConfig loadConfig(const std::string& filePath);

private:
    std::string decryptFile(const std::string& filePath);
    EmulatorConfig parseConfig(const std::string& configData);
};

#endif 