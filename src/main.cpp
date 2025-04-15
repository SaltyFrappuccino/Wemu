#include "emulator.h"
#include "config_loader.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <config_file.wemu>" << std::endl;
        return 1;
    }

    std::string configPath = argv[1];

    try {
        ConfigLoader loader;
        EmulatorConfig config = loader.loadConfig(configPath);

        Emulator wemu(config);
        wemu.run();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Wemu simulation finished." << std::endl;

    return 0;
} 