#include <iostream>
#include <stdexcept>

#include <cstdlib>
#include <errno.h>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <pcap.h>

struct Remote {
    int sock;
    sockaddr_in saddr;
    Remote(const char *ipaddr, int port) {
        sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0)
            throw std::runtime_error(std::string("Cannot create UDP socket: ") + strerror(errno));

        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(ipaddr);
        saddr.sin_port = htons(port);

        if (connect(sock, (const sockaddr *)&saddr, sizeof(saddr)) < 0)
            throw std::runtime_error(std::string("Cannot connect: ") + strerror(errno));
    }

    void onPacket(const u_char *pack, const pcap_pkthdr &header) {
        send(sock, pack, header.len, 0);
    }

    ~Remote() {
        if (sock >= 0)
            close(sock);
    }
};

struct Pcap {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_pkthdr header;

    Pcap(const char *dev) {
        handle = pcap_open_live(dev, BUFSIZ, 0, /* promiscuous = */ 0, errbuf);
        if (!handle)
            throw std::runtime_error(std::string("Could not open dev ") + dev + " for sniffing: " + errbuf);
    }

    static void got_packet(u_char *args, const pcap_pkthdr *header, const u_char *packet) {
        Remote *r = reinterpret_cast<Remote *>(args);
        r->onPacket(packet, *header);
    }

    void sniff(Remote &r) {
        pcap_loop(handle, -1, got_packet, reinterpret_cast<u_char *>(&r));
    }

    ~Pcap() {
        if (handle)
            pcap_close(handle);
    }
};

int usage(const char *argv0) {
    std::cout << "USAGE: " << argv0 << " <dev> <remote ip> <remote port>" << std::endl;
    return 1;
}

int main(int argc, char **argv) {
    try {
        if (argc < 4)
            return usage(argv[0]);
        Remote r(argv[2], atoi(argv[3]));
        Pcap p(argv[1]);
        p.sniff(r);
    } catch (const std::runtime_error &e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}
