#pragma once

#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "mac.hpp"

class Param {
private:
    std::string interface;
    Mac APMAC, StationMAC;
    bool auth;
public:
    Param() = default;

    bool parse(int argc, char* argv[]) {
        char* endptr;

        if(argc < 3) {
            this->printUsageError();
            return false;
        }

        interface = argv[1];
        APMAC = Mac(argv[2]);
        StationMAC = Mac::broadcastMac();

        for(int i = 2; i < argc; i++) {
            if(argv[i][0] == '-' and argv[i] == "-auth") auth = true;
            else StationMAC = Mac(argv[i]);
        }
    }

    bool isAuth() const { return this->auth; }
    Mac getAPMAC() const { return this->APMAC; }
    Mac getStationMAC() const { return this->StationMAC; }
    std::string getInterface() const { return this->interface; }

    void printUsageError() {
        std::cerr << "syntax : deauth-attack <interface> <ap mac> [<station mac>] [-auth]\n";
        std::cerr << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB" << std::endl;
    }
};
