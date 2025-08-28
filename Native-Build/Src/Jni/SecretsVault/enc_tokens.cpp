#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <iomanip>
#include <cstring>

extern "C" {
    #include "aes.h"
}

uint8_t masterKey[32] = {
    '.', 'A', 'x', '0', 'B', 'x', '1', 'C',
    'x', '2', 'D', 'x', '3', 'E', 'x', '4',
    'F', 'x', '5', 'G', 'x', '6', 'H', 'x',
    '7', 'I', 'x', '8', 'J', 'x', '9', '.'
};

uint8_t iv[16] = {0};

size_t padPKCS7(std::vector<uint8_t>& data) {
    size_t padLen = 16 - (data.size() % 16);
    data.insert(data.end(), padLen, static_cast<uint8_t>(padLen));
    return data.size();
}

void aes256_encrypt_cbc(std::vector<uint8_t>& data, const uint8_t* key, const uint8_t* iv) {
    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, data.data(), data.size());
}

void printByteArrayToFile(std::ofstream& out, const std::string& id, const std::vector<uint8_t>& data) {
    out << "strMapSecure[\"" << id << "\"] = {";
    for (size_t i = 0; i < data.size(); ++i) {
        if (i % 16 == 0) out << "\n  ";
        out << "0x" << std::hex << std::uppercase << std::setw(2)
            << std::setfill('0') << static_cast<int>(data[i]) << ", ";
    }
    out << "\n};\n\n";
}

int main() {
    std::map<std::string, std::string> inputStrings = {
        {"github_token_getdata", "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"},
        {"github_token_putdata", "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"}
    };

    std::ofstream out("encrypted_tokens.txt");
    if (!out.is_open()) {
        std::cerr << "❌ Failed to open output file.\n";
        return 1;
    }

    for (const auto& pair : inputStrings) {
        std::vector<uint8_t> data(pair.second.begin(), pair.second.end());
        padPKCS7(data);
        aes256_encrypt_cbc(data, masterKey, iv);
        printByteArrayToFile(out, pair.first, data);
        std::cout << "✅ Encrypted: " << pair.first << " (" << data.size() << " bytes)\n";
    }

    out.close();
    std::cout << "📦 All encrypted data written to encrypted_tokens.txt\n";
    return 0;
}
