//
// Created by dell on 2023/6/22.
//

#ifndef SM3_SM3_H
#define SM3_SM3_H


#include <iostream>
#include <bitset>
#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <chrono>


using namespace std;


#define u_32 uint32_t


class SM3 {
public:
    SM3();
    string hash(string message);

private:
    static string messagePadding(string message);
    static vector<u_32> messageExtension(const string& message);
    static string CF(const string& V_i, vector<u_32> B_i);
    inline static string zeroPadding(const string& input, int padLen);
    static string strTobin(const string& input);
    inline static string u32ToHex(u_32 input);
    inline static u_32 circleLS(u_32 input, int n);
    inline static u_32 T(int j);
    inline static u_32 FF(u_32 x, u_32 y, u_32 z, int j);
    inline static u_32 GG(u_32 x, u_32 y, u_32 z, int j);
    inline static u_32 P0(u_32 input);
    inline static u_32 P1(u_32 input);

    string IV;
};


#endif//SM3_SM3_H#pragma once
