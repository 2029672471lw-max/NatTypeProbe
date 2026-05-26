#pragma once
#include <random>
#include <cstdint>
#include <chrono>

inline uint32_t random32(uint32_t minNum,uint32_t maxNum){
    static std::mt19937 gen(std::chrono::system_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<uint32_t> dist(minNum,maxNum);
    return dist(gen);
}
inline uint16_t random16(uint16_t minNum,uint16_t maxNum){
    static std::mt19937 gen(std::chrono::system_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<uint16_t> dist(minNum,maxNum);
    return dist(gen);
}
inline uint8_t random8(uint8_t minNum,uint8_t maxNum){
    static std::mt19937 gen(std::chrono::system_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<uint8_t> dist(minNum,maxNum);
    return dist(gen);
}