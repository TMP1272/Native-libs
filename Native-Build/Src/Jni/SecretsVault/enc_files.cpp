#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstring>

extern "C" {
    #include "aes.h"
}

// 🔐 Khóa AES
uint8_t masterKey[32] = {
    '.', 'A', 'x', '0', 'B', 'x', '1', 'C',
    'x', '2', 'D', 'x', '3', 'E', 'x', '4',
    'F', 'x', '5', 'G', 'x', '6', 'H', 'x',
    '7', 'I', 'x', '8', 'J', 'x', '9', '.'
};

uint8_t iv[16] = {0};

// 📥 Đọc file thành vector<uint8_t>
std::vector<uint8_t> readFileAsBytes(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "❌ Cannot open " << path << "\n";
        return {};
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    file.close();
    return buffer;
}

// 🧂 Padding PKCS7
size_t padPKCS7(std::vector<uint8_t>& data) {
    size_t padLen = 16 - (data.size() % 16);
    data.insert(data.end(), padLen, static_cast<uint8_t>(padLen));
    return data.size();
}

// 🔐 Mã hóa AES CBC
void aes256_encrypt_cbc(std::vector<uint8_t>& data, const uint8_t* key, const uint8_t* iv) {
    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, data.data(), data.size());
}

// 📄 Ghi ra file
void printByteArrayToFile(std::ofstream& out, const std::string& id, const std::vector<uint8_t>& data) {
    out << "keyMapSecure[\"" << id << "\"] = {";
    for (size_t i = 0; i < data.size(); ++i) {
        if (i % 16 == 0) out << "\n  ";
        out << "0x" << std::hex << std::uppercase << std::setw(2)
            << std::setfill('0') << static_cast<int>(data[i]) << ", ";
    }
    out << "\n};\n\n";
}

int main() {
    std::vector<std::string> filesToEncrypt = {
        "key.pem"
    };

    std::ofstream out("encrypted_files.txt");
    if (!out.is_open()) {
        std::cerr << "❌ Failed to open output file.\n";
        return 1;
    }

    for (const std::string& filename : filesToEncrypt) {
        std::vector<uint8_t> content = readFileAsBytes(filename);
        if (content.empty()) {
            std::cerr << "⚠️ Skipping empty or unreadable file: " << filename << "\n";
            continue;
        }

        padPKCS7(content);
        aes256_encrypt_cbc(content, masterKey, iv);
        printByteArrayToFile(out, filename, content);
        std::cout << "✅ Encrypted: " << filename << " (" << content.size() << " bytes)\n";
    }

    out.close();
    std::cout << "📦 All encrypted data written to encrypted_files.txt\n";
    return 0;
}
