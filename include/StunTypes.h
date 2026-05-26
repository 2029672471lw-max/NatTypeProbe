#pragma once
#include <cstdint>
#include <array>
#define STUNMSG_MAX_LEN 2048
#define STUNMSG_MAX_UNKNOWN 8
#define StunServerDefaultPort 3478
typedef std::array<uint8_t,12> TransactionID;

struct StunAddress4{
    uint16_t port;
    uint32_t ip;

    bool operator==(const StunAddress4& other){
        return port==other.port && ip==other.ip;
    }
};

struct StunMessageHeader{
    uint16_t MessageType;
    uint16_t MessageLength;
    uint32_t MagicCookie=0x2112A442;
    TransactionID TransactionID;
};

struct StunAtrAdderess4{
    uint8_t padding;
    uint8_t family;
    StunAddress4 address;
};

struct StunAtrResponsePort{
    uint8_t port;
    uint8_t padding;
};

struct StunAtrErrorCode{
    uint16_t padding;
    uint8_t class_;
    uint8_t number;
    char reason[128];
    uint16_t reasonSize;
};

struct StunAtrUnknownAtr{
    uint16_t attrType[STUNMSG_MAX_UNKNOWN];
    uint16_t AtrNum;
};

enum class StunMsgType : std::uint16_t{
    BindRequest = 0x0001,
    BindResponse = 0x0101,
    BindErrorResponse = 0x0111
};

enum class StunMsgAtr : std::uint16_t{
    ChangeResquest = 0x0003,
    ErrorCode = 0x0009,
    UnknownAttribute = 0x000A,
    XorMappedAddress = 0x0020,
    OtherAddress = 0x802C,
    ResponseOrigin = 0x802B
};