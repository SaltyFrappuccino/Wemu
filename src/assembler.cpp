#include "assembler.h"
#include "device.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include <algorithm>
#include <stdexcept>

namespace {
    std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\r\n");
        if (std::string::npos == first) {
            return str;
        }
        size_t last = str.find_last_not_of(" \t\r\n");
        return str.substr(first, (last - first + 1));
    }

    std::string to_upper(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::toupper);
        return s;
    }
}

void Assembler::reportError(const std::string& message, int lineNumber) {
    std::cerr << "Assembly Error";
    if (lineNumber > 0) {
        std::cerr << " (Line " << lineNumber << ")";
    }
    std::cerr << ": " << message << std::endl;
}

AssembledProgram Assembler::assemble(const std::string& asmFilePath) {
    AssembledProgram result;
    symbolTable_.clear();
    parsedLines_.clear();
    startAddress_ = 0x100; 

    std::ifstream file(asmFilePath);
    if (!file.is_open()) {
        reportError("Could not open assembly file: " + asmFilePath);
        return result;
    }

    std::cout << "Assembling " << asmFilePath << "..." << std::endl;

    if (!firstPass(file)) {
        return result;
    }

    if (!secondPass(result.bytecode)) {
        return result;
    }

    result.loadAddress = startAddress_;
    result.success = true;
    std::cout << "Assembly successful. Code size: " << result.bytecode.size()
              << " bytes. Load address: 0x" << std::hex << result.loadAddress << std::dec << std::endl;
    return result;
}

bool Assembler::firstPass(std::ifstream& file) {
    std::string line;
    int lineNumber = 0;
    currentAddress_ = startAddress_; 

    while (std::getline(file, line)) {
        lineNumber++;
        ParsedLine pLine = parseLine(line, lineNumber);
        if (pLine.mnemonic.empty() && pLine.label.empty()) continue; 

        if (!pLine.label.empty()) {
            if (symbolTable_.count(pLine.label)) {
                reportError("Duplicate label '" + pLine.label + "'", lineNumber);
                return false;
            }
            symbolTable_[pLine.label] = { currentAddress_ };
            std::cout << "  Found Label: " << pLine.label << " at 0x" << std::hex << currentAddress_ << std::dec << std::endl;
        }

        if (!pLine.mnemonic.empty()) {
            if (to_upper(pLine.mnemonic) == ".ORG") {
                if (pLine.operands.size() != 1) {
                    reportError(".ORG directive requires exactly one address operand", lineNumber);
                    return false;
                }
                bool ok = false;
                startAddress_ = parseOperand(pLine.operands[0], pLine, ok);
                if (!ok) {
                    reportError("Invalid address for .ORG directive: " + pLine.operands[0], lineNumber);
                    return false;
                }
                currentAddress_ = startAddress_;
                std::cout << "  Found .ORG directive. Setting start address to 0x" << std::hex << startAddress_ << std::dec << std::endl;
                pLine.instructionSize = 0; 
            } else {
                pLine.instructionSize = calculateInstructionSize(pLine);
                if (pLine.instructionSize < 0) {
                    return false; 
                }
                pLine.address = currentAddress_;
                currentAddress_ += pLine.instructionSize;
            }
            parsedLines_.push_back(pLine);
        } else if (!pLine.label.empty()) {
            pLine.address = currentAddress_;
            pLine.instructionSize = 0;
            parsedLines_.push_back(pLine); 
        }
    }
    return true;
}

bool Assembler::secondPass(std::vector<uint8_t>& bytecode) {
    bytecode.clear();
    for (const auto& pLine : parsedLines_) {
        if (!pLine.mnemonic.empty() && to_upper(pLine.mnemonic) != ".ORG") {
            if (!encodeInstruction(pLine, bytecode)) {
                return false;
            }
        }
    }
    return true;
}

Assembler::ParsedLine Assembler::parseLine(const std::string& line, int lineNumber) {
    ParsedLine result;
    result.lineNumber = lineNumber;
    std::string lineNoComment = line;
    size_t commentPos = line.find(';');
    if (commentPos != std::string::npos) {
        lineNoComment = line.substr(0, commentPos);
    }

    std::string trimmedLine = trim(lineNoComment);
    if (trimmedLine.empty()) {
        return result;
    }

    size_t firstSpace = trimmedLine.find_first_of(" \t");
    std::string firstPart = trimmedLine;
    std::string rest = "";

    if (firstSpace != std::string::npos) {
        firstPart = trim(trimmedLine.substr(0, firstSpace));
        rest = trim(trimmedLine.substr(firstSpace + 1));
    }

    if (!firstPart.empty() && firstPart.back() == ':') {
        result.label = firstPart.substr(0, firstPart.length() - 1);
        if (rest.empty()) return result; 
        
        size_t mnemonicSpace = rest.find_first_of(" \t");
        if (mnemonicSpace != std::string::npos) {
            result.mnemonic = trim(rest.substr(0, mnemonicSpace));
            rest = trim(rest.substr(mnemonicSpace + 1));
        } else {
            result.mnemonic = rest;
            rest = "";
        }
    } else {
        result.mnemonic = firstPart;
    }

    std::stringstream ssOperands(rest);
    std::string operand;
    while (std::getline(ssOperands, operand, ',')) {
        result.operands.push_back(trim(operand));
    }

    return result;
}

int Assembler::calculateInstructionSize(const ParsedLine& line) {
    std::string mnemonic = to_upper(line.mnemonic);
    const auto& ops = line.operands;

    if (mnemonic == "NOP" || mnemonic == "HALT") return 1;
    if (mnemonic == "LOAD_IMM") return 1 + 1 + 4; 
    if (mnemonic == "STORE_REG" || mnemonic == "LOAD_MEM") return 1 + 1 + 4; 
    if (mnemonic == "ADD" || mnemonic == "SUB") return 1 + 3;
    if (mnemonic == "CMP_REG") return 1 + 2;
    if (mnemonic == "JMP" || mnemonic == "JE" || mnemonic == "JNE") return 1 + 4;

    reportError("Unknown mnemonic '" + line.mnemonic + "'", line.lineNumber);
    return -1;
}


uint8_t Assembler::parseRegister(const std::string& regStr, bool& ok) {
    ok = false;
    if (regStr.length() != 2 || (regStr[0] != 'R' && regStr[0] != 'r')) return 0;
    try {
        int regNum = std::stoi(regStr.substr(1));
        if (regNum >= 0 && regNum < 8) {
            ok = true;
            return static_cast<uint8_t>(regNum);
        }
    } catch(...) {}
    return 0;
}

uint32_t Assembler::parseOperand(const std::string& operand, const ParsedLine& context, bool& ok) {
    ok = false;
    std::string trimmedOp = trim(operand);

    if (symbolTable_.count(trimmedOp)) {
        ok = true;
        return symbolTable_[trimmedOp].address;
    }

    try {
        size_t processed = 0;
        uint32_t value = 0;
        if (trimmedOp.size() > 2 && trimmedOp.substr(0, 2) == "0x") {
            value = std::stoul(trimmedOp.substr(2), &processed, 16);
            processed += 2;
        } else {
            value = std::stoul(trimmedOp, &processed, 10);
        }
        if (processed == trimmedOp.length()) {
             ok = true;
             return value;
        }
    } catch (...) {}

    reportError("Invalid operand or unknown label '" + operand + "'", context.lineNumber);
    return 0;
}

bool Assembler::encodeInstruction(const ParsedLine& line, std::vector<uint8_t>& bytecode) {
    std::string mnemonic = to_upper(line.mnemonic);
    const auto& ops = line.operands;
    bool ok = false;

    auto write8 = [&](uint8_t val) { bytecode.push_back(val); };
    auto write32 = [&](uint32_t val) {
        bytecode.push_back(val & 0xFF);
        bytecode.push_back((val >> 8) & 0xFF);
        bytecode.push_back((val >> 16) & 0xFF);
        bytecode.push_back((val >> 24) & 0xFF);
    };

    if (mnemonic == "NOP") {
        if (ops.size() != 0) { reportError("NOP takes no operands", line.lineNumber); return false; }
        write8(Opcode::NOP);
    } else if (mnemonic == "HALT") {
         if (ops.size() != 0) { reportError("HALT takes no operands", line.lineNumber); return false; }
         write8(Opcode::HALT);
    } else if (mnemonic == "LOAD_IMM") { 
        if (ops.size() != 2) { reportError("LOAD_IMM requires 2 operands (reg, value)", line.lineNumber); return false; }
        uint8_t reg = parseRegister(ops[0], ok);
        if (!ok) { reportError("Invalid register for LOAD_IMM: " + ops[0], line.lineNumber); return false; }
        uint32_t value = parseOperand(ops[1], line, ok);
         if (!ok) return false; 
        write8(Opcode::LOAD_IMM); write8(reg); write32(value);
    } else if (mnemonic == "STORE_REG") { 
        if (ops.size() != 2) { reportError("STORE_REG requires 2 operands (reg, address)", line.lineNumber); return false; }
        uint8_t reg = parseRegister(ops[0], ok);
         if (!ok) { reportError("Invalid register for STORE_REG: " + ops[0], line.lineNumber); return false; }
        uint32_t addr = parseOperand(ops[1], line, ok);
        if (!ok) return false; 
        write8(Opcode::STORE_REG); write8(reg); write32(addr);
     } else if (mnemonic == "LOAD_MEM") { 
        if (ops.size() != 2) { reportError("LOAD_MEM requires 2 operands (reg, address)", line.lineNumber); return false; }
         uint8_t reg = parseRegister(ops[0], ok);
        if (!ok) { reportError("Invalid register for LOAD_MEM: " + ops[0], line.lineNumber); return false; }
         uint32_t addr = parseOperand(ops[1], line, ok);
        if (!ok) return false;
         write8(Opcode::LOAD_MEM); write8(reg); write32(addr);
    } else if (mnemonic == "ADD" || mnemonic == "SUB") { 
         if (ops.size() != 3) { reportError(mnemonic + " requires 3 register operands", line.lineNumber); return false; }
         uint8_t r1 = parseRegister(ops[0], ok); if (!ok) { reportError("Invalid dest register for " + mnemonic + ": " + ops[0], line.lineNumber); return false; }
         uint8_t r2 = parseRegister(ops[1], ok); if (!ok) { reportError("Invalid src1 register for " + mnemonic + ": " + ops[1], line.lineNumber); return false; }
         uint8_t r3 = parseRegister(ops[2], ok); if (!ok) { reportError("Invalid src2 register for " + mnemonic + ": " + ops[2], line.lineNumber); return false; }
         write8(mnemonic == "ADD" ? Opcode::ADD : Opcode::SUB); write8(r1); write8(r2); write8(r3);
     } else if (mnemonic == "CMP_REG") { 
         if (ops.size() != 2) { reportError("CMP_REG requires 2 register operands", line.lineNumber); return false; }
         uint8_t r1 = parseRegister(ops[0], ok); if (!ok) { reportError("Invalid src1 register for CMP_REG: " + ops[0], line.lineNumber); return false; }
         uint8_t r2 = parseRegister(ops[1], ok); if (!ok) { reportError("Invalid src2 register for CMP_REG: " + ops[1], line.lineNumber); return false; }
         write8(Opcode::CMP_REG); write8(r1); write8(r2);
    } else if (mnemonic == "JMP" || mnemonic == "JE" || mnemonic == "JNE") {
        if (ops.size() != 1) { reportError(mnemonic + " requires 1 address/label operand", line.lineNumber); return false; }
        uint32_t addr = parseOperand(ops[0], line, ok);
        if (!ok) return false;
        Opcode op = (mnemonic == "JMP" ? Opcode::JMP : (mnemonic == "JE" ? Opcode::JE : Opcode::JNE));
        write8(op); write32(addr);
    } else {
        reportError("Internal error: Cannot encode unknown mnemonic '" + line.mnemonic + "'", line.lineNumber);
        return false;
    }

    return true;
} 