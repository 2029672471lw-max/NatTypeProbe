#include "StunNatDetect.h"

bool StunNatDetecter::Initialize(uint32_t ip, uint16_t port)
{
    WSADATA wsaData;
    int ret=WSAStartup(MAKEWORD(2,2),&wsaData);
    if(ret){
        std::cerr << "WSAStartup failed: " << ret << std::endl;
        return -1;
    }

    if((MapFd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))<0 || (FilterFd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))<0){
        std::cerr << "Socket createded fail:" << WSAGetLastError() << std::endl;
        return -1;
    }

    if(port==0) port=random16(0x4000,0x7fff);
    sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    if(ip!=0 && ip!=INADDR_LOOPBACK) addr.sin_addr.s_addr=htonl(ip);
    else addr.sin_addr.s_addr=htonl(INADDR_ANY);
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);

    sockaddr_in addr2=addr;
    addr2.sin_port=htons(++port);

    if(bind(MapFd,(sockaddr*)&addr,sizeof(addr)) || bind(FilterFd,(sockaddr*)&addr2,sizeof(addr2))){
        std::cerr << "Socket createded fail:" << WSAGetLastError() << std::endl;
        return -1;
    }
    
    return 0;
}

void StunNatDetecter::Reset()
{

    count=0;
    hasError=false;
    MaptestI=false;
    MaptestII=false;
    MaptestIII=false;
    FiltertestI=false;
    FiltertestII=false;
    FiltertestIII=false;
}

bool StunNatDetecter::SetDest(std::string name, uint16_t port)
{
    hostent* h = gethostbyname(name.c_str());
    if(h==nullptr){
        std::cerr << "url is invalid, gethostbyname failed:" << WSAGetLastError() << std::endl;
        hasError=true;
        return -1;
    }

    uint32_t ip_net;
    memcpy(&ip_net, h->h_addr_list[0], 4);
    dest.ip = ntohl(ip_net);

    dest.port=port;
    return 0;
}

void StunNatDetecter::Detect()
{
    while(count<8){
        int fdSetSize=0;
        fd_set fdSet;
        FD_ZERO(&fdSet); fdSetSize=0;
        FD_SET(MapFd,&fdSet); fdSetSize=(MapFd+1>fdSetSize) ? MapFd+1 : fdSetSize;
        FD_SET(FilterFd,&fdSet); fdSetSize=(FilterFd+1>fdSetSize) ? FilterFd+1 : fdSetSize;

        timeval tv;
        tv.tv_sec=0;
        tv.tv_usec=500*1000;
        if(count==0) tv.tv_usec=0;

        int ret = select(fdSetSize,&fdSet,NULL,NULL,&tv);
        if(ret<0){
            std::cerr << "Select error: " << WSAGetLastError() << std::endl;
            hasError=true;
            return;
        }
        else if(ret==0){
            count++;
            if(!MaptestI){
                if(StunSendTest(MapFd,dest,10)<0){
                    hasError=true;
                    std::cerr << "TestMessage 10 sent failed" << std::endl;
                };
            }
            if(!MaptestII && MaptestI){
                if(StunSendTest(MapFd,DestMaptestII,11)<0){
                    hasError=true;
                    std::cerr << "TestMessage 11 sent failed" << std::endl;
                };
            }
            if(!MaptestIII && MaptestII){
                if(StunSendTest(MapFd,DestMaptestIII,12)<0){
                    hasError=true;
                    std::cerr << "TestMessage 12 sent failed" << std::endl;
                };
            }

            if(!FiltertestI){
                if(StunSendTest(FilterFd,dest,20)<0){
                    hasError=true;
                    std::cerr << "TestMessage 20 sent failed" << std::endl;
                }
            }
            if(!FiltertestII){
                if(StunSendTest(FilterFd,dest,21)<0){
                    hasError=true;
                    std::cerr << "TestMessage 21 sent failed" << std::endl;
                }
            }
            if(!FiltertestIII){
                if(StunSendTest(FilterFd,dest,22)<0){
                    hasError=true;
                    std::cerr << "TestMessage 22 sent failed" << std::endl;
                }
            }
        }
        else{
            count=0;
            int recvnum=ret;
            while(recvnum--){
                if(FD_ISSET(MapFd,&fdSet)){
                    StunMessage req;
                    memset(&req,0,sizeof(req));
                    StunGetMsg(MapFd,req);
                    //std::cout << "Received message with TransactionID: " << (int)req.header.TransactionID[0] << std::endl;
                    switch(req.header.TransactionID[0]){
                        case 10:
                            MaptestI=true;
                            AddressMaptestI=req.XorMappedAddress.address;
                            DestMaptestII=req.OtherAddress.address;
                            break;
                        case 11:
                            MaptestII=true;
                            AddressMaptestII=req.XorMappedAddress.address;
                            DestMaptestIII=req.OtherAddress.address;
                            break;
                        case 12:
                            AddressMaptestIII=req.XorMappedAddress.address;
                            MaptestIII=true;
                            break;
                        default:
                            hasError=true;
                            break;
                    }
                }
                if(FD_ISSET(FilterFd,&fdSet)){
                    StunMessage req;
                    memset(&req,0,sizeof(req));
                    StunGetMsg(FilterFd,req);
                    //std::cout << "Received message with TransactionID: " << (int)req.header.TransactionID[0] << std::endl;
                    switch(req.header.TransactionID[0]){
                        case 20:
                            FiltertestI=true;
                            break;
                        case 21:
                            FiltertestI=true;
                            break;
                        case 22:
                            FiltertestI=true;
                            break;
                        default:
                            hasError=true;
                            break;
                    }
                }
            }
        }
    }
    // AddressMaptestI.ip=htonl(AddressMaptestI.ip);
    // AddressMaptestII.ip=htonl(AddressMaptestII.ip);
    // AddressMaptestIII.ip=htonl(AddressMaptestIII.ip);
    // DestMaptestII.ip=htonl(DestMaptestII.ip);
    // DestMaptestIII.ip=htonl(DestMaptestIII.ip);

    // std::cout << "AddressMaptestI: " << inet_ntoa(*(in_addr*)&AddressMaptestI.ip) << ":" << AddressMaptestI.port << std::endl
    // << "AddressMaptestII: " << inet_ntoa(*(in_addr*)&AddressMaptestII.ip) << ":" << AddressMaptestII.port << std::endl
    // << "AddressMaptestIII: " << inet_ntoa(*(in_addr*)&AddressMaptestIII.ip) << ":" << AddressMaptestIII.port << std::endl
    // << "DestMaptestII: " << inet_ntoa(*(in_addr*)&DestMaptestII.ip) << ":" << DestMaptestII.port << std::endl
    // << "DestMaptestIII: " << inet_ntoa(*(in_addr*)&DestMaptestIII.ip) << ":" << DestMaptestIII.port << std::endl;
}

void StunNatDetecter::DescribeMap()
{
    if(AddressMaptestI == AddressMaptestII && AddressMaptestII == AddressMaptestIII){
        std::cout << "Mapping is Endpoint-Independent Mapping" << std::endl;
        return;
    }
    else if(AddressMaptestI == AddressMaptestII){
        std::cout << "Mapping is Address-Dependent Mapping" << std::endl;
        return;
    }
    else{
        std::cout << "Mapping is Address & Port-Dependent Mapping" << std::endl;
        return;
    }
    
}

void StunNatDetecter::DescribeFilter()
{
    if(FiltertestII){
        std::cout << "Filtering is Endpoint-Independent Filtering" << std::endl;
        return;
    }
    else if(FiltertestIII){
        std::cout << "Filtering is Address-Dependent Filtering" << std::endl;
        return;
    }
    else{
        std::cout << "Filtering is Address & Port-Dependent Filtering" << std::endl;
        return;
    }
}