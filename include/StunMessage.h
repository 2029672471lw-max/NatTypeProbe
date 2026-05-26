#pragma once
#include "StunTypes.h"
#include <iostream>
#include <winsock2.h>
#include <OtherApi.h>

struct StunMessage{
    StunMessageHeader header;

    bool hasChangeRequest=false;
    uint32_t ChangeRequest;

    bool hasXorMappedAddress=false;
    StunAtrAdderess4 XorMappedAddress;

    bool hasOtherAddress=false;
    StunAtrAdderess4 OtherAddress;

    // bool hasResponseOrigin=false;
    // StunAtrAdderess4 ResponseOrigin;
    
    bool hasErrorCode=false;
    StunAtrErrorCode ErrorCode;

    bool hasUnknownAttribute=false;
    StunAtrUnknownAtr UnknownAttribute;

};

int StunSendTest(SOCKET& fd,StunAddress4& dest,uint8_t TestNum);

void StunMsgBuild(StunMessage& msg,int TestNum);

unsigned int StunEncodeMsg(const StunMessage& msg,char* buf,unsigned int len);

int StunGetMsg(SOCKET& fd,StunMessage& msg);

template<class T>
char* encode(char* ptr,T data);

char* encode16(char* ptr,uint16_t data);
char* encode32(char* ptr,uint32_t data);
