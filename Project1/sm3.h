#pragma once
#include <iostream>
typedef unsigned int uint32;

uint32 lshift(uint32 val, unsigned int n)
{
    n = n % 32;
    uint32 size = sizeof(val) * 8;
    n = n % size;
    return (val >> (size - n) | (val << n));
}

unsigned int IV[8] =
{ 0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e };

unsigned char arr[64] = { 0 };
unsigned int T[64] = { 0 };

unsigned int W0[68];
unsigned int W1[64];

void Tj()
{
    for (unsigned int i = 0; i < 16; i++)
        T[i] = 0x79cc4519;
    for (unsigned int i = 16; i < 64; i++)
        T[i] = 0x7a879d8a;
}

unsigned int FF(unsigned int x, unsigned int y, unsigned int z, unsigned int j)
{
    if (j <= 15 && j >= 0)
        return x ^ y ^ z;
    else if (j >= 16 && j <= 63)
        return (x & y) | (x & z) | (y & z);
    return 0;
}

unsigned int GG(unsigned int x, unsigned int y, unsigned int z, unsigned int j)
{
    if (j >= 0 && j <= 15)
        return x ^ y ^ z;
    else if (j >= 16 && j <= 63)
        return (x & y) | ((~x) & z);
    return 0;
}

unsigned int P0(unsigned int x)
{
    return x ^ lshift(x, 9) ^ lshift(x, 17);
}

unsigned int P1(unsigned int x)
{
    return x ^ lshift(x, 15) ^ lshift(x, 23);
}



void extend(unsigned char* arr)
{
    unsigned int j;
    for (j = 0; j < 16; j++)
        W0[j] = arr[j * 4 + 0] << 24 | arr[j * 4 + 1] << 16 | arr[j * 4 + 2] << 8 | arr[j * 4 + 3];
    for (j = 16; j < 68; j++)
        W0[j] = P1(W0[j - 16] ^ W0[j - 9] ^ (lshift(W0[j - 3], 15))) ^ (lshift(W0[j - 13], 7)) ^ W0[j - 6];
    for (j = 0; j < 64; j++)
        W1[j] = W0[j] ^ W0[j + 4];
}

unsigned int compress(unsigned char* arr)
{
    unsigned int j;
    unsigned int set[8];
    unsigned int SS1, SS2, TT1, TT2;
    extend(arr);
    for (int i = 0; i < 8; i++)
    {
        set[i] = IV[i];
    }
    for (j = 0; j < 64; j++)
    {
        SS1 = lshift((lshift(set[0], 12)) + set[4] + (lshift(T[j], j)), 7);
        SS2 = SS1 ^ (lshift(set[0], 12));
        TT1 = FF(set[0], set[1], set[2], j) + set[3] + SS2 + W1[j];
        TT2 = GG(set[4], set[5], set[6], j) + set[7] + SS1 + W0[j];
        set[3] = set[2];
        set[2] = lshift(set[1], 9);
        set[1] = set[0];
        set[0] = TT1;
        set[7] = set[6];
        set[6] = lshift(set[5], 19);
        set[5] = set[4];
        set[4] = P0(TT2);
    }
    for (int i = 0; i < 8; i++)
    {
        IV[i] = set[i] ^ IV[i];
    }
    return 1;
}


void sm3(unsigned char* data, unsigned int len)
{
    unsigned int i;
    unsigned int left = 0;
    unsigned long long bits = 0;
    int limit = len / 64;
    for (i = 0; i < limit; i++)
    {
        memcpy(arr, data + i * 64, 64);
        compress(arr);
    }
    bits = len * 8;
    left = len % 64;
    memset(&arr[left], 0, 64 - left);
    memcpy(arr, data + i * 64, left);
    arr[left] = 128;
    if (left <= 55)
    {
        for (i = 0; i < 8; i++)
            arr[56 + i] = bits >> ((8 - 1 - i) * 8);
        compress(arr);
    }
    else
    {
        compress(arr);
        memset(arr, 0, 64);
        for (i = 0; i < 8; i++)
            arr[56 + i] = bits >> ((8 - 1 - i) * 8);
        compress(arr);
    }
}