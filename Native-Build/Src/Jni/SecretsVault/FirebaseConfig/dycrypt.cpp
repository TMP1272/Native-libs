#include <jni.h>
#include <string>
#include <map>
#include <vector>
#include <cstring>
#include <iostream>
#include "aes.h"

// 🔐 Khóa AES chung
uint8_t masterKey[32] = {
    '.', 'A', 'x', '0', 'B', 'x', '1', 'C',
    'x', '2', 'D', 'x', '3', 'E', 'x', '4',
    'F', 'x', '5', 'G', 'x', '6', 'H', 'x',
    '7', 'I', 'x', '8', 'J', 'x', '9', '.'
};

uint8_t iv[16] = {0};

// 🧠 Hàm loại bỏ padding PKCS7
std::string removePKCS7Padding(std::vector<uint8_t>& data) {
    if (data.empty()) return "";

    uint8_t padLen = data.back();
    if (padLen == 0 || padLen > 16) {
        std::cerr << "❌ Invalid padding length: " << static_cast<int>(padLen) << "\n";
        return "";
    }

    size_t dataLen = data.size();
    for (size_t i = dataLen - padLen; i < dataLen; ++i) {
        if (data[i] != padLen) {
            std::cerr << "❌ Padding mismatch at byte " << i << "\n";
            return "";
        }
    }

    return std::string(reinterpret_cast<char*>(data.data()), dataLen - padLen);
}

// 🔐 Giải mã AES CBC
void aes256_decrypt_cbc(std::vector<uint8_t>& data, const uint8_t* key, const uint8_t* iv) {
    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, data.data(), data.size());
}

// 🔓 Hàm giải mã token
std::string decryptToken(const std::map<std::string, std::vector<uint8_t>>& map, const std::string& id) {
    auto it = map.find(id);
    if (it == map.end()) {
        std::cerr << "⚠️ Không tìm thấy ID: " << id << "\n";
        return "";
    }

    const std::vector<uint8_t>& encrypted = it->second;
    if (encrypted.empty() || encrypted.size() % 16 != 0) {
        std::cerr << "❌ Dữ liệu không hợp lệ hoặc không đủ block size\n";
        return "";
    }

    std::vector<uint8_t> decrypted(encrypted);
    aes256_decrypt_cbc(decrypted, masterKey, iv);
    std::string result = removePKCS7Padding(decrypted);

    if (result.empty()) {
        std::cerr << "❌ Giải mã thất bại hoặc padding sai\n";
    }

    return result;
}

//
// 🔐 TokenProvider
//
std::map<std::string, std::vector<uint8_t>> tokenMapSecure;

void initTokenProvider() {
    tokenMapSecure["github_token_getdata"] = {
        0x88, 0x34, 0x11, 0x94, 0xF1, 0x76, 0x88, 0x71, 0x3A, 0xB3, 0xDC, 0x55, 0x17, 0x28, 0x3E, 0x60, 
        0x14, 0x38, 0xF9, 0xFA, 0xAF, 0x22, 0xF5, 0x06, 0x35, 0x9D, 0xE1, 0x27, 0x41, 0x41, 0x9C, 0x63, 
        0x3B, 0xA7, 0x49, 0xAE, 0x83, 0x76, 0x42, 0xB0, 0xA1, 0x6B, 0x77, 0x15, 0x66, 0x7B, 0x0B, 0x63, 
        0x16, 0xF3, 0x70, 0xCF, 0x2B, 0x72, 0xF8, 0x36, 0x34, 0x37, 0x6E, 0x90, 0xF4, 0x4E, 0xDE, 0x1C, 
        0x63, 0xB2, 0xC7, 0x60, 0xD4, 0xC4, 0xFA, 0x74, 0x91, 0xD9, 0x6C, 0x39, 0xC5, 0xC4, 0x11, 0xDD, 
        0x1A, 0x15, 0xF7, 0xE3, 0xC8, 0xD8, 0xF0, 0xDF, 0x4E, 0xD6, 0xD2, 0xFA, 0x72, 0x96, 0x73, 0x34
    };

    tokenMapSecure["github_token_putdata"] = {
        0x88, 0x34, 0x11, 0x94, 0xF1, 0x76, 0x88, 0x71, 0x3A, 0xB3, 0xDC, 0x55, 0x17, 0x28, 0x3E, 0x60, 
        0xF5, 0xE9, 0x65, 0x14, 0x67, 0xCE, 0xA1, 0x0F, 0xD6, 0xB3, 0x2B, 0xC7, 0xAB, 0xA3, 0x43, 0xD6, 
        0xD4, 0xAE, 0xF8, 0x95, 0x62, 0x38, 0xCD, 0x09, 0xCD, 0x58, 0xDD, 0x9F, 0xA0, 0x6A, 0x4E, 0x4A, 
        0x89, 0x92, 0x74, 0xC7, 0xCA, 0xCD, 0x09, 0x70, 0x01, 0x1E, 0x70, 0xBF, 0x3B, 0x56, 0xBA, 0xEB, 
        0x28, 0x62, 0x3A, 0xA3, 0xAF, 0xCE, 0xBA, 0xAD, 0xB3, 0x3C, 0x9C, 0xF5, 0xB9, 0xDB, 0xB2, 0xF2, 
        0xE6, 0x18, 0x83, 0x99, 0x28, 0x70, 0xE6, 0xF6, 0x07, 0x37, 0xD3, 0x80, 0x6D, 0x08, 0xBA, 0x44
    };
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_tmp1272_lib_nativelib_TokenProvider_getToken(JNIEnv *env, jobject, jstring idStr) {
    initTokenProvider();
    const char* idChars = env->GetStringUTFChars(idStr, nullptr);
    std::string id(idChars);
    env->ReleaseStringUTFChars(idStr, idChars);

    std::string result = decryptToken(tokenMapSecure, id);
    return result.empty() ? nullptr : env->NewStringUTF(result.c_str());
}

//
// 🕵️ SecureStore
//
std::map<std::string, std::vector<uint8_t>> strMapSecure;

void initSecureStore() {
    strMapSecure["api_url"] = {
        0xBC, 0x62, 0x87, 0xE7, 0xB0, 0x1D, 0xCB, 0xBB, 0x2E, 0xB6, 0x93, 0xB5, 0xB9, 0x5F, 0xF9, 0xF0, 
        0x39, 0xAA, 0xF3, 0xB8, 0x81, 0xAF, 0x8E, 0xEC, 0xAD, 0xB9, 0xF4, 0x3C, 0xC8, 0x6F, 0x43, 0x2D
    };

    strMapSecure["project_code"] = {
        0x31, 0xC6, 0xA7, 0xDC, 0x3C, 0xD3, 0x06, 0x8C, 0x71, 0xE4, 0x35, 0x4B, 0x10, 0x8E, 0xBE, 0xF6
    };
}

std::map<std::string, std::vector<uint8_t>> apikeyMapSecure;

void initFirebase() {
    apikeyMapSecure["firebase_api_key"] = {
        0xBC, 0x62, 0x87, 0xE7, 0xB0, 0x1D, 0xCB, 0xBB, 0x2E, 0xB6, 0x93, 0xB5, 0xB9, 0x5F, 0xF9, 0xF0, 
        0x39, 0xAA, 0xF3, 0xB8, 0x81, 0xAF, 0x8E, 0xEC, 0xAD, 0xB9, 0xF4, 0x3C, 0xC8, 0x6F, 0x43, 0x2D
    };
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_tmp1272_lib_nativelib_SecureStore_getValue(JNIEnv *env, jobject, jstring idStr) {
    initSecureStore();
    const char* idChars = env->GetStringUTFChars(idStr, nullptr);
    std::string id(idChars);
    env->ReleaseStringUTFChars(idStr, idChars);

    std::string result = decryptToken(strMapSecure, id);
    return result.empty() ? nullptr : env->NewStringUTF(result.c_str());
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_tmp1272_lib_nativelib_FirebaseKeyProvider_getFirebaseApiKey(JNIEnv *env, jobject) {
    initFirebase();
    std::string result = decryptToken(apikeyMapSecure, "firebase_api_key");
    return result.empty() ? nullptr : env->NewStringUTF(result.c_str());
}

//
// 🧾 Thêm Class Mới
//
