#include "config_loader.h"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <iostream> 
#include <filesystem>
#include <vector>

std::vector<uint8_t> xorCrypt(const std::vector<uint8_t>& data, const std::string& key) {
    if (key.empty()) {
        return data;
    }
    std::vector<uint8_t> result = data;
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key[i % key.size()];
    }
    return result;
}

// Заглушка для дешифрования - теперь читает бинарно и применяет XOR
std::string ConfigLoader::decryptFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate); 
    if (!file.is_open()) {
        throw std::runtime_error("Could not open config file: " + filePath);
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
         throw std::runtime_error("Could not read config file: " + filePath);
    }

    std::string encryptionKey = "";

    std::vector<uint8_t> decryptedBuffer = xorCrypt(buffer, encryptionKey);

     if (!encryptionKey.empty()) {
         std::cout << "Config file decrypted using XOR." << std::endl;
     } else {
         std::cout << "Warning: Config file encryption key is empty. Reading as plain text." << std::endl;
     }

    return std::string(decryptedBuffer.begin(), decryptedBuffer.end());
}

EmulatorConfig ConfigLoader::parseConfig(const std::string& configData) {
    EmulatorConfig config;
    std::stringstream ss(configData);
    std::string line;

    std::cout << "Parsing config data..." << std::endl;
    while (std::getline(ss, line)) {
        // std::cout << "Read line: " << line << std::endl; // Отладка
        if (line.empty() || line[0] == '#') continue;

        size_t equalsPos = line.find('=');
        if (equalsPos == std::string::npos) continue;

        std::string key = line.substr(0, equalsPos);
        std::string value = line.substr(equalsPos + 1);

        key.erase(0, key.find_first_not_of(" \t\n\r\f\v"));
        key.erase(key.find_last_not_of(" \t\n\r\f\v") + 1);
        value.erase(0, value.find_first_not_of(" \t\n\r\f\v"));
        value.erase(value.find_last_not_of(" \t\n\r\f\v") + 1);

        std::cout << "Parsed key: '" << key << "', value: '" << value << "'" << std::endl; // Отладка

        if (key == "device.type") {
            config.deviceConfig.deviceType = value;
        } else if (key == "device.ramMB") {
            try {
                config.deviceConfig.ramSizeMB = std::stoi(value);
            } catch (const std::invalid_argument& /*e*/) {
                 std::cerr << "Warning: Invalid value for device.ramMB: " << value << std::endl;
            } catch (const std::out_of_range& /*e*/) {
                 std::cerr << "Warning: Value out of range for device.ramMB: " << value << std::endl;
            }
        } else if (key == "security.type") {
            config.securityConfig.type = value;
        } else if (key == "program.assembly_file") {
            config.assemblyFilePath = value;
        } else {
            if (key.rfind("device.", 0) == 0) {
                 config.deviceConfig.parameters[key.substr(7)] = value;
            } else if (key.rfind("security.", 0) == 0) {
                 config.securityConfig.parameters[key.substr(9)] = value;
            }
        }
    }
    std::cout << "Config parsing finished." << std::endl;
    return config;
}

EmulatorConfig ConfigLoader::loadConfig(const std::string& filePath) {
    std::cout << "Loading config from: " << filePath << std::endl;

    std::filesystem::path configPath(filePath);
    std::string configDir = configPath.has_parent_path() ? configPath.parent_path().string() : ".";
    std::cout << "Config directory: " << configDir << std::endl;

    std::string decryptedData = decryptFile(filePath);
    if (decryptedData.empty()) {
        throw std::runtime_error("Decrypted config data is empty.");
    }
    EmulatorConfig config = parseConfig(decryptedData);
    config.configFileDir = configDir;
    return config;
} 