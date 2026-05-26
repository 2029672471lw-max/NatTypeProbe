#include "StunMessage.h"

int StunSendTest(SOCKET& fd, StunAddress4 &dest, uint8_t TestNum)
{
    StunMessage req;
    StunMsgBuild(req,TestNum);
    char buf[STUNMSG_MAX_LEN];
    unsigned int len = STUNMSG_MAX_LEN;
    len=StunEncodeMsg(req,buf,len);

    sockaddr_in Dest;
    Dest.sin_family=AF_INET;
    Dest.sin_addr.s_addr=htonl(dest.ip);
    Dest.sin_port=htons(dest.port);
    
    if(sendto(fd,buf,len,0,(sockaddr*)&Dest,sizeof(Dest))<0){
        std::cerr << "sendto failed:" << WSAGetLastError() << std::endl;
        return -1;
    }

    //std::cout << "TestMessage " << (int)TestNum << " sent" << std::endl;
    return 0;
}

void StunMsgBuild(StunMessage& req, int TestNum)
{
    
    req.header.MessageType =(uint16_t)StunMsgType::BindRequest;
    {
        req.header.TransactionID[0]=TestNum;
        for(int i=1;i<12;i++){
            req.header.TransactionID[i]=random8(0,255);
        }
    }

    if(TestNum==21){
        req.hasChangeRequest=true;
        req.ChangeRequest=0x04;
    }
    else if(TestNum==22){
        req.hasChangeRequest=true;
        req.ChangeRequest=0x02;
    }
}

unsigned int StunEncodeMsg(const StunMessage &msg, char *buf, unsigned int len)
{
    char* ptr = buf;
    
    ptr=encode16(ptr,msg.header.MessageType);
        
    ptr=encode16(ptr,0);
    ptr=encode32(ptr,msg.header.MagicCookie);
    ptr=encode(ptr,msg.header.TransactionID);
       
    if(msg.hasChangeRequest){
        ptr=encode16(ptr,(uint16_t)StunMsgAtr::ChangeResquest);
        ptr=encode16(ptr,sizeof(msg.ChangeRequest));
        ptr=encode32(ptr,msg.ChangeRequest);
    }

    if(msg.hasErrorCode){
        ptr=encode16(ptr,(uint16_t)StunMsgAtr::ErrorCode);
        ptr=encode16(ptr,4+msg.ErrorCode.reasonSize);
        ptr=encode16(ptr,msg.ErrorCode.padding);
        *ptr++=msg.ErrorCode.class_;
        *ptr++=msg.ErrorCode.number;
        memcpy(ptr,msg.ErrorCode.reason,msg.ErrorCode.reasonSize);
        ptr+=msg.ErrorCode.reasonSize;
    }
    
    if(msg.hasUnknownAttribute){
        ptr=encode16(ptr,(uint16_t)StunMsgAtr::UnknownAttribute);
        ptr=encode16(ptr,2*msg.UnknownAttribute.AtrNum);
        for(int i=0;i<msg.UnknownAttribute.AtrNum;++i){
            ptr = encode16(ptr,msg.UnknownAttribute.attrType[i]);
        }
        if(msg.UnknownAttribute.AtrNum%2) ptr = encode16(ptr,0);
    }

    encode(buf+2,(uint16_t)(ptr-buf-20));
    return ptr-buf;
}

int StunGetMsg(SOCKET& fd,StunMessage &msg)
{
    char buf[STUNMSG_MAX_LEN];
    int ret = recvfrom(fd,buf,STUNMSG_MAX_LEN,0,0,0);
    if(ret<0){
        std::cerr << "RecvFrom error:" << WSAGetLastError() << std::endl;
        return -1;
    }
    int copy_len=0;
    int cur_len=0;

    
    memcpy(&msg,buf,sizeof(msg.header));
    msg.header.MessageType=ntohs(msg.header.MessageType);
    msg.header.MessageLength=ntohs(msg.header.MessageLength);
    msg.header.MagicCookie=ntohl(msg.header.MagicCookie);
    if (msg.header.MagicCookie != 0x2112A442) {
        std::cerr << "Invalid Magic Cookie" << std::endl;
        return -1;
    }
    copy_len+=sizeof(msg.header);
    
    while(copy_len<ret){
        uint16_t TypeId;
        memcpy(&TypeId,buf+copy_len,sizeof(TypeId));
        TypeId=ntohs(TypeId);
        copy_len+=sizeof(TypeId);
        uint16_t AtrLen=0;
        memcpy(&AtrLen,buf+copy_len,sizeof(AtrLen));
        AtrLen=ntohs(AtrLen);
        copy_len+=sizeof(AtrLen);
        switch (TypeId)
        {
        case (uint16_t)StunMsgAtr::XorMappedAddress:
        {
            cur_len = copy_len;
            msg.hasXorMappedAddress=true;
            memcpy(&msg.XorMappedAddress.padding,buf+copy_len,sizeof(msg.XorMappedAddress.padding));
            copy_len+=sizeof(msg.XorMappedAddress.padding);
            memcpy(&msg.XorMappedAddress.family,buf+copy_len,sizeof(msg.XorMappedAddress.family));
            copy_len+=sizeof(msg.XorMappedAddress.family);
            
            uint16_t nport;
            memcpy(&nport,buf+copy_len,sizeof(nport));
            copy_len+=sizeof(nport);
            msg.XorMappedAddress.address.port = ntohs(nport) ^ (msg.header.MagicCookie >> 16);
            uint32_t nip;
            memcpy(&nip,buf+copy_len,sizeof(nip));
            copy_len+=sizeof(nip);
            msg.XorMappedAddress.address.ip = ntohl(nip) ^ msg.header.MagicCookie;
            if(cur_len+AtrLen!=copy_len){
                std::cerr << "XorMappedAddress AtrLen error" << std::endl;
                return -1;
            }
            break;
        }
        case (uint16_t)StunMsgAtr::OtherAddress:
        {
            cur_len = copy_len;
            msg.hasOtherAddress=true;
            memcpy(&msg.OtherAddress.padding,buf+copy_len,sizeof(msg.OtherAddress.padding));
            copy_len+=sizeof(msg.OtherAddress.padding);
            memcpy(&msg.OtherAddress.family,buf+copy_len,sizeof(msg.OtherAddress.family));
            copy_len+=sizeof(msg.OtherAddress.family);

            uint16_t nport;
            memcpy(&nport,buf+copy_len,sizeof(nport));
            copy_len+=sizeof(nport);
            msg.OtherAddress.address.port = ntohs(nport);
            uint32_t nip;
            memcpy(&nip,buf+copy_len,sizeof(nip));
            copy_len+=sizeof(nip);
            msg.OtherAddress.address.ip=ntohl(nip);
            
            if(cur_len+AtrLen!=copy_len){
                std::cerr << "OtherAddress AtrLen error" << std::endl;
                return -1;
            }
            break;
        }
        // case (uint16_t)StunMsgAtr::ResponseOrigin:
        // {
        //     cur_len = copy_len;
        //     msg.hasResponseOrigin=true;
        //     memcpy(&msg.ResponseOrigin.padding,buf+copy_len,sizeof(msg.ResponseOrigin.padding));
        //     copy_len+=sizeof(msg.ResponseOrigin.padding);
        //     memcpy(&msg.ResponseOrigin.family,buf+copy_len,sizeof(msg.ResponseOrigin.family));
        //     copy_len+=sizeof(msg.ResponseOrigin.family);

        //     uint16_t nport;
        //     memcpy(&nport,buf+copy_len,sizeof(nport));
        //     copy_len+=sizeof(nport);
        //     msg.ResponseOrigin.address.port = ntohs(nport);
        //     uint32_t nip;
        //     memcpy(&nip,buf+copy_len,sizeof(nip));
        //     copy_len+=sizeof(nip);
        //     msg.ResponseOrigin.address.ip=ntohl(nip);
            
        //     if(cur_len+AtrLen!=copy_len){
        //         std::cerr << "ResponseOrigin AtrLen error" << std::endl;
        //         return -1;
        //     }
        //     break;
        // }
        case (uint16_t)StunMsgAtr::ErrorCode:
            msg.hasErrorCode=true;
            copy_len+=AtrLen;
            break;
        case (uint16_t)StunMsgAtr::UnknownAttribute:
            msg.hasUnknownAttribute=true;
            copy_len+=AtrLen;
            break;
        default:
            copy_len+=AtrLen;
            break;
        }
    }
    return 0;
}

template<class T>
char* encode(char* ptr,T data){
    memcpy(ptr,&data,sizeof(data));
    return ptr+=sizeof(data);
}

char* encode16(char *ptr, uint16_t data)
{
    data=htons(data);
    memcpy(ptr,&data,sizeof(data));
    return ptr+=2;
}

char* encode32(char *ptr, uint32_t data)
{
    data=htonl(data);
    memcpy(ptr,&data,sizeof(data));
    return ptr+=4;
}
