#pragma once

#include <iostream>
#include <csignal>
#include <atomic>
#include <pcap.h>
#include <unistd.h>

#include "802-11.hpp"
#include "param.hpp"

extern std::atomic<bool> isEnd;

void initDeauthPacket(deauth_packet& deauthPacket, const Param& param);
void initAuthPacket(deauth_packet& deauthPacket, const Param& param);
bool deauth_attack(const Param& param);
