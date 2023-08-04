#include<iostream>
#include<bitset>
#include<sstream>
#include<fstream>
using namespace std;
void dump_buf(char* ciphertext_32, int lenth);
void sm3(char plaintext[], int* hash_val);

int find_sm3_collision() {
    cout << "信息: ";
    char plaintext[] = "abc";
    cout << plaintext << endl;

    int hash_val[8];
    int hash_val2[8];
    int hash_val3[8];

    sm3(plaintext, hash_val);
    cout << "hash为：" << endl;
    dump_buf((char*)hash_val, 32);

    sm3(plaintext, hash_val2);
    while (true) {
        memcpy(hash_val3, hash_val2, 32);
        sm3((char*)hash_val2, hash_val2);
        if (!memcmp(hash_val, hash_val2, 2)) {
            cout << "找到碰撞：" << endl;
            dump_buf((char*)hash_val3, 32);
            cout << "Hash为：" << endl;
            dump_buf((char*)hash_val2, 32);
            break;
        }
    }

    cout << 2 * 8 << "bit的信息" << endl;
    return 0;
}

int main() {
    clock_t startTime = clock();
    find_sm3_collision();
    clock_t endTime = clock();
    cout << "时间：" << double(endTime - startTime) / CLOCKS_PER_SEC << "s" << endl;

    system("pause");
    return 0;