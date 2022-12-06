#pragma once

#include "mac.hpp"



#pragma pack(push, 1)
struct radiotap {
    uint8_t it_version;     // radiotap version, always 0
    uint8_t it_pad;         // padding (or alignment)
    uint16_t it_len;        // overall radiotap header length
    uint32_t it_present; // (first) present word

    enum presentFlag: uint32_t {
        Tsft = 0,
        Flags = 1,
        Rate = 2,
        Channel = 3,
        Fhss = 4,
        AntennaSignal = 5,
        AntennaNoise = 6,
        LockQuality = 7,
        TxAttenuation = 9,
        DbTxAttenuation = 9,
        DbmTxPower = 10,
        Antenna = 11,
        DbAntennaSignal = 12,
        DbAntennaNoise = 13,
        RxFlags = 14,
        TxFlags = 15,
        RtsRetries = 16,
        DataRetries = 17,
        XChannel = 18,
        Mcs = 19,
        AMpdu = 20,
        Vht = 21,
        Timestamp = 22,
        He = 23,
        HeMu = 24,
        HeMuOtherUser = 25,
        ZeroLenghPsdu = 26,
        LSig = 27,
        Tlv = 28,
        RadiotapNamespace = 29,
        VendorNamespace = 30,
        Ext = 31
    };

    radiotap() = default;
    uint8_t getVersion() const { this->it_version; }
    uint8_t getPad() const { this->it_pad; }
    uint16_t getLen() const { this->it_len; }
    presentFlag getPresent() const { this->it_present; }
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Dot11 {
    uint8_t version:2;
    uint8_t type:2;
    uint8_t subtype:4;
    uint8_t flags;
    uint16_t duration;

    enum Type: uint8_t {
        MANAGEMENT_FRAMES       = 0,    // 802.11 Management Frames
        CONTROL_FRAMES          = 1,    // 802.11 Control Frames
        DATA_FRAMES             = 2,    // 802.11 Data Frames
        EXTENSION_FRAME         = 3     // 802.11 Extension Frames
    };

    enum Subtype: uint8_t {
        // In case of 802.11 Management Frames
        Association_request     = 0x0,
        Association_response    = 0x1,
        Reassociation_request   = 0x2,
        Reassociation_response  = 0x3,
        Probe_request           = 0x4,
        Probe_response          = 0x5,
        Timing_Advertisemant    = 0x6,
        Beacon                  = 0x8,
        ATIM                    = 0x9,
        Disassociation          = 0xa,
        Authentication          = 0xb,
        Deauthentication        = 0xc,
        Action                  = 0xd,
        Action_no_ack           = 0xe,

        // In case of 802.11 Control Frames
        Beamforming_report_poll = 0x14,
        VHT_NDP_Announcement    = 0x15,
        Control_frame_extension = 0x16,
        Control_wrapper         = 0x17,
        Block_ACK_request       = 0x18,
        Block_ACK               = 0x19,
        PS_Poll                 = 0x1a,
        Ready_To_Send           = 0x1b,
        Clear_To_Send           = 0x1c,
        ACK                     = 0x1d,
        CF_End                  = 0x1e,
        CF_End_CF_Ack           = 0x1f,

        // In case of 802.11 Data Frames
        Data                    = 0x20,
        Data_CF_Ack             = 0x21,
        Data_CF_Poll            = 0x22,
        Data_CF_Ack_CF_Poll     = 0x23,
        Null                    = 0x24,
        CF_Ack                  = 0x25,
        CF_Poll                 = 0x26,
        CF_Ack_CF_Poll          = 0x27,
        QoS_Data                = 0x28,
        QoS_Data_CF_Ack         = 0x29,
        QoS_Data_CF_Poll        = 0x2a,
        QoS_Data_CF_Ack_CF_Poll = 0x2b,
        QoS_Null                = 0x2c,
        QoS_CF_Poll             = 0x2e,
        QoS_CF_Ack_CF_Poll      = 0x2f,

        // In case of 802.11 Extension Frames
        DMG_Beacon              = 0x30,
        S1G_Beacon              = 0x31
    };

    Dot11() = default;

    uint8_t getTypeSubtype() { return ((type << 4) or (subtype)); }
    uint8_t getType() { return type; }
    uint8_t getSubtype() { return subtype; }
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Dot11Hdr : Dot11 {
    Mac addr1_;
    Mac addr2_;
    Mac addr3_;
    uint8_t frag:4;
    uint16_t seq:12;

    Mac getReceiverMac() const { return addr1_; }
    Mac getTargetMac() const { return addr2_; }
    Mac getBSSID() const { return addr3_; }
};
#pragma pack(pop)

#pragma pack(push, 1)
struct deauth_packet {
    radiotap radio;

    uint8_t dataRate;
    uint8_t zero;
    uint16_t tx;

    Dot11Hdr dot11;
    uint16_t reasonCode;

    deauth_packet() = default;
};
#pragma pack(pop)
