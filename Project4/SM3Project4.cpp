

#include "SM3.h"

#include <utility>

SM3::SM3() {
    IV = "7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e";
}

string SM3::strTobin(const std::string& input) {
    unsigned char tmp;
    string res;
    for (char c : input) {
        tmp = static_cast<int>(c);
        res.append(bitset<8>(tmp).to_string());
    }
    return res;
}

string SM3::zeroPadding(const std::string& input, int padLen) {
    string zeroString(padLen, '0');
    return input + zeroString;
}

string SM3::u32ToHex(u_32 input) {
    stringstream ss;
    ss << hex << setw(8) << setfill('0') << input;
    return ss.str();
}

u_32 SM3::circleLS(u_32 input, int n) {
    return (input << n) | (input >> (32 - n));
}

u_32 SM3::T(int j) {
    if (j >= 0 && j <= 15)
        return u_32(stoul("79cc4519", nullptr, 16));
    else
        return u_32(stoul("7a879d8a", nullptr, 16));
}

u_32 SM3::FF(u_32 x, u_32 y, u_32 z, int j) {
    if (j >= 0 && j <= 15)
        return x ^ y ^ z;
    else
        return (x & y) | (x & z) | (y & z);
}

u_32 SM3::GG(u_32 x, u_32 y, u_32 z, int j) {
    if (j >= 0 && j <= 15)
        return x ^ y ^ z;
    else
        return (x & y) | (~x & z);
}

u_32 SM3::P0(u_32 input) {
    return input ^ circleLS(input, 9) ^ circleLS(input, 17);
}

u_32 SM3::P1(u_32 input) {
    return input ^ circleLS(input, 15) ^ circleLS(input, 23);
}

string SM3::messagePadding(std::string message) {
    string M_bin = strTobin(std::move(message));

    int len = M_bin.length();
    string padOfLen = bitset<32>(len).to_string();
    string zeroString(64 - padOfLen.length(), '0');
    padOfLen = zeroString + padOfLen;

    int zeroLen;
    if ((len + 1) % 512 <= 448) zeroLen = 448 - len - 1;
    else
        zeroLen = 512 - len + 448 - 1;

    M_bin += "1";
    string M = zeroPadding(M_bin, zeroLen);
    M += padOfLen;

    return M;
}

vector<u_32> SM3::messageExtension(const std::string& group) {
    vector<u_32> W;
    vector<u_32> W_;

    string tmp;
    for (int j = 0; j < 16; j++) {
        tmp = group.substr(j * 32, 32);
        W.push_back(stoul(tmp, nullptr, 2));
    }

    u_32 tmp1, tmp2, tmp3;
    for (int j = 16; j < 68; j++) {
        tmp1 = P1(W[j - 16] ^ W[j - 9] ^ circleLS(W[j - 3], 15));
        tmp2 = circleLS(W[j - 13], 7);
        tmp3 = W[j - 6];
        W.push_back(tmp1 ^ tmp2 ^ tmp3);
    }

    for (int j = 0; j < 64; j++)
        W_.push_back(W[j] ^ W[j + 4]);

    W.insert(W.end(), W_.begin(), W_.end());

    return W;
}

string SM3::CF(const string& V_i, vector<u_32> B_i) {
    u_32 A = u_32(stoul(V_i.substr(0, 8), nullptr, 16));
    u_32 B = u_32(stoul(V_i.substr(8, 8), nullptr, 16));
    u_32 C = u_32(stoul(V_i.substr(16, 8), nullptr, 16));
    u_32 D = u_32(stoul(V_i.substr(24, 8), nullptr, 16));
    u_32 E = u_32(stoul(V_i.substr(32, 8), nullptr, 16));
    u_32 F = u_32(stoul(V_i.substr(40, 8), nullptr, 16));
    u_32 G = u_32(stoul(V_i.substr(48, 8), nullptr, 16));
    u_32 H = u_32(stoul(V_i.substr(56, 8), nullptr, 16));
    u_32 A_ = u_32(stoul(V_i.substr(0, 8), nullptr, 16));
    u_32 B_ = u_32(stoul(V_i.substr(8, 8), nullptr, 16));
    u_32 C_ = u_32(stoul(V_i.substr(16, 8), nullptr, 16));
    u_32 D_ = u_32(stoul(V_i.substr(24, 8), nullptr, 16));
    u_32 E_ = u_32(stoul(V_i.substr(32, 8), nullptr, 16));
    u_32 F_ = u_32(stoul(V_i.substr(40, 8), nullptr, 16));
    u_32 G_ = u_32(stoul(V_i.substr(48, 8), nullptr, 16));
    u_32 H_ = u_32(stoul(V_i.substr(56, 8), nullptr, 16));

    u_32 SS1, SS2, TT1, TT2;
    for (int j = 0; j < 64; j++) {
        SS1 = circleLS(circleLS(A, 12) + E + circleLS(T(j), j), 7);
        SS2 = SS1 ^ circleLS(A, 12);
        TT1 = FF(A, B, C, j) + D + SS2 + B_i[68 + j];
        TT2 = GG(E, F, G, j) + H + SS1 + B_i[j];
        D = C;
        C = circleLS(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = circleLS(F, 19);
        F = E;
        E = P0(TT2);
    }
    string a = u32ToHex(A ^ A_);
    string b = u32ToHex(B ^ B_);
    string c = u32ToHex(C ^ C_);
    string d = u32ToHex(D ^ D_);
    string e = u32ToHex(E ^ E_);
    string f = u32ToHex(F ^ F_);
    string g = u32ToHex(G ^ G_);
    string h = u32ToHex(H ^ H_);

    return a + b + c + d + e + f + g + h;
}

string SM3::hash(std::string message) {
    string M_bin = messagePadding(message);

    int blockNum = M_bin.length() / 512;
    vector<vector<u_32>> B;
    B.reserve(blockNum);
    for (int i = 0; i < blockNum; i++) {
        string group = M_bin.substr(i * 512, 512);
        B.emplace_back(messageExtension(group));
    }

    string V = IV;
    for (int i = 0; i < blockNum; i++)
        V = CF(V, B[i]);

    return V;
}
#include "SM3.h"

int main() {
    string data = "202100150108";
    SM3 sm3;

    string hashValue;
    auto t1 = chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000000; i++)
        hashValue = sm3.hash(data); #include "SM3.h"

#include <utility>

        SM3::SM3() {
        IV = 0x7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e;
    }

    string SM3::strTobin(const std::string & input) {
        string res;
        for (char c : input) {
            res += bitset<8>(static_cast<unsigned char>(c)).to_string();
        }
        return res;
    }

    string SM3::zeroPadding(const std::string & input, int padLen) {
        return input + string(padLen, '0');
    }

    string SM3::u32ToHex(u32 input) {
        char hex[9];
        snprintf(hex, sizeof(hex), "%08x", input);
        return hex;
    }

    u32 SM3::circleLS(u32 input, int n) {
        return (input << n) | (input >> (32 - n));
    }

    u32 SM3::T(int j) {
        return (j >= 0 && j <= 15) ? 0x79cc4519 : 0x7a879d8a;
    }

    u32 SM3::FF(u32 x, u32 y, u32 z, int j) {
        return (j >= 0 && j <= 15) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
    }

    u32 SM3::GG(u32 x, u32 y, u32 z, int j) {
        return (j >= 0 && j <= 15) ? (x ^ y ^ z) : ((x & y) | (~x & z));
    }

    u32 SM3::P0(u32 input) {
        return input ^ circleLS(input, 9) ^ circleLS(input, 17);
    }

    u32 SM3::P1(u32 input) {
        return input ^ circleLS(input, 15) ^ circleLS(input, 23);
    }

    string SM3::messagePadding(std::string message) {
        string M_bin = strTobin(std::move(message));

        int len = M_bin.length();
        int padLen = (len + 1) % 512 <= 448 ? 448 - len - 1 : 512 - len + 448 - 1;

        M_bin += "1";
        string M = zeroPadding(M_bin, padLen);

        int high = len >> 29;
        int low = len << 3;
        M += static_cast<char>(high >> 24);
        M += static_cast<char>(high >> 16);
        M += static_cast<char>(high >> 8);
        M += static_cast<char>(high);
        M += static_cast<char>(low >> 24);
        M += static_cast<char>(low >> 16);
        M += static_cast<char>(low >> 8);
        M += static_cast<char>(low);

        return M;
    }

    void SM3::messageExtension(const std::string & group, vector<u32>&W) {
        W.resize(68);
        for (int j = 0; j < 16; j++) {
            W[j] = static_cast<u32>(stoul(group.substr(j * 32, 32), nullptr, 2));
        }

        for (int j = 16; j < 68; j++) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ circleLS(W[j - 3], 15)) ^ circleLS(W[j - 13], 7) ^ W[j - 6];
        }

        for (int j = 0; j < 64; j++) {
            W[j + 16] = W[j] ^ W[j + 4];
        }
    }

    void SM3::CF(const u32 * V_i, const vector<u32>&B_i, u32 * V) {
        u32 A = V_i[0];
        u32 B = V_i[1];
        u32 C = V_i[2];
        u32 D = V_i[3];
        u32 E = V_i[4];
        u32 F = V_i[5];
        u32 G = V_i[6];
        u32 H = V_i[7];
        u32 A_ = V_i[0];
        u32 B_ = V_i[1];
        u32 C_ = V_i[2];
        u32 D_ = V_i[3];
        u32 E_ = V_i[4];
        u32 F_ = V_i[5];
        u32 G_ = V_i[6];
        u32 H_ = V_i[7];

        u32 SS1, SS2, TT1, TT2;
        for (int j = 0; j < 64; j++) {
            SS1 = circleLS(circleLS(A, 12) + E + circleLS(T(j), j), 7);
            SS2 = SS1 ^ circleLS(A, 12);
            TT1 = FF(A, B, C, j) + D + SS2 + B_i[68 + j];
            TT2 = GG(E, F, G, j) + H + SS1 + B_i[j];
            D = C;
            C = circleLS(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = circleLS(F, 19);
            F = E;
            E = P0(TT2);
        }
        V[0] = A ^ A_;
        V[1] = B ^ B_;
        V[2] = C ^ C_;
        V[3] = D ^ D_;
        V[4] = E ^ E_;
        V[5] = F ^ F_;
        V[6] = G ^ G_;
        V[7] = H ^ H_;
    }

    string SM3::hash(std::string message) {
        string M_bin = messagePadding(message);

        int blockNum = M_bin.length() / 512;
        vector<u32> B(132);
        u32 V[8];

        for (int i = 0; i < blockNum; i++) {
            string group = M_bin.substr(i * 512, 512);
            messageExtension(group, B);
            CF(V, B, V);
        }

        string hashValue;
        for (int i = 0; i < 8; i++) {
            hashValue += u32ToHex(V[i]);
        }

        return hashValue;
    }

    int main() {
        string data = "202100150108";
        SM3 sm3;

        string hashValue;
        auto t1 = chrono::high_resolution_clock::now();
        for (int i = 0; i < 1000000; i++) {
            hashValue = sm3.hash(data);
        }
        auto t2 = chrono::high_resolution_clock::now();
        auto t3 = chrono::duration_cast<chrono::milliseconds>(t2 - t1);

        cout << "加密: " << data << '\n';
        cout << "Hash: " << hashValue << '\n';
        cout << "总时间: " << t3.count() << "ms\n";
        cout << "平均时间: " << t3.count() / double(1000000) << "ms\n";

        return 0;
    }

    auto t2 = chrono::high_resolution_clock::now();
    auto t3 = chrono::duration_cast<chrono::milliseconds>(t2 - t1);

    cout << "加密: " << data << '\n';
    cout << "Hash: " << hashValue << '\n';
    cout << "总时间: " << t3.count() << "ms\n";
    cout << "平均时间: " << t3.count() / double(1000000) << "ms\n";

    return 0;
}