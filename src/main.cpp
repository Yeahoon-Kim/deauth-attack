#include "deauth-attack.hpp"

std::atomic<bool> isEnd;

void interruptHandler(const int signo) {
    switch(signo) {
        case SIGINT:
            std::cout << "Keyboard Interrupt\n";
            break;
        case SIGTERM:
            std::cout << "Terminate signal\n";
            break;
        default: break;
    }

    isEnd.store(true);
}

int main(int argc, char* argv[]) {
    signal(SIGINT, interruptHandler);
    signal(SIGTERM, interruptHandler);

    Param param;

    param.parse(argc, argv);
    deauth_attack(param);

    return 0;
}
