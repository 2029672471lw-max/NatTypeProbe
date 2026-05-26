#include "StunNatDetect.h"

int main() {
    std::string dest="stun.hot-chilli.net";
    StunNatDetecter detecter;
    if(detecter.Initialize(0,0)){
        std::cerr << "Initialize failed" << std::endl;
    }
    if(detecter.SetDest(dest)){
        std::cerr << "SetDest failed" << std::endl;
        return 1;
    }
    detecter.Detect();
    if(detecter.HasError()){
        std::cerr << "Detect failed" << std::endl;
        return 1;
    }
    detecter.DescribeMap();
    detecter.DescribeFilter();
    return 0;
}
