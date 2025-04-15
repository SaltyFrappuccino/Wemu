#ifndef ASSEMBLER_H
#define ASSEMBLER_H

#include <string>
#include <vector>
#include <cstdint>
#include <map>

struct AssembledProgram {
    std::vector<uint8_t> bytecode;
    uint32_t loadAddress = 0x100;
    bool success = false;
};

class Assembler {
public:
    AssembledProgram assemble(const std::string& asmFilePath);

private:
    struct LabelInfo {
        uint32_t address;
    };

    struct ParsedLine {
        std::string label;
        std::string mnemonic;
        std::vector<std::string> operands;
        int lineNumber = 0;
        uint32_t address = 0; 
        int instructionSize = 0;
    };

    std::map<std::string, LabelInfo> symbolTable_;
    uint32_t currentAddress_ = 0;
    uint32_t startAddress_ = 0x100;
    std::vector<ParsedLine> parsedLines_;

    bool firstPass(std::ifstream& file);
    bool secondPass(std::vector<uint8_t>& bytecode);

    ParsedLine parseLine(const std::string& line, int lineNumber);
    int calculateInstructionSize(const ParsedLine& line);
    bool encodeInstruction(const ParsedLine& line, std::vector<uint8_t>& bytecode);
    uint32_t parseOperand(const std::string& operand, const ParsedLine& context, bool& ok);
    uint8_t parseRegister(const std::string& regStr, bool& ok);

    void reportError(const std::string& message, int lineNumber = -1);
};

#endif 