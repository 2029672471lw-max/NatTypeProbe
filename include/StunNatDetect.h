#pragma once
#include <iostream>
#include "StunMessage.h"
#include <winsock2.h>
#include <ws2tcpip.h>

class StunNatDetecter
{
public:
    bool Initialize(uint32_t ip,uint16_t port);
    void Reset();
    bool SetDest(std::string name,uint16_t port=StunServerDefaultPort);
    void Detect();
    void DescribeMap();
    void DescribeFilter();
    bool HasError(){ return hasError; }
private:
    SOCKET MapFd;
    SOCKET FilterFd;
    int count=0;
    bool hasError=false;
    bool MaptestI=false;
    bool MaptestII=false;
    bool MaptestIII=false;
    bool FiltertestI=false;
    bool FiltertestII=false;
    bool FiltertestIII=false;
    
    StunAddress4 dest;
    StunAddress4 DestMaptestII;
    StunAddress4 DestMaptestIII;
    StunAddress4 OtherAddress;

    StunAddress4 AddressMaptestI;
    StunAddress4 AddressMaptestII;
    StunAddress4 AddressMaptestIII;
};