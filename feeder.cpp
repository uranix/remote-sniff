#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/limits.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <sys/ioctl.h>

#include <fcntl.h>
#include <errno.h>
#include <cstring>
#include <unistd.h>

#include <iostream>
#include <stdexcept>
#include <string>

#include <memory>

struct Feeder {
    virtual void feed(const char *buf, const int len) = 0;
    virtual const char *name() const = 0;
    virtual ~Feeder() { }
};

struct Tap : public Feeder {
    int fd;
    ifreq ifr;

    Tap() {
        const char *clonedev = "/dev/net/tun";

        fd = open(clonedev, O_RDWR);
        if (fd < 0)
            throw std::runtime_error(std::string("Could not open ") + clonedev + ": " + strerror(errno));

        memset(&ifr, 0, sizeof(ifr));

        ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
        ifr.ifr_name[0] = 0;

        int err = ioctl(fd, TUNSETIFF, (void *)&ifr);
        if (err < 0)
            throw std::runtime_error(std::string("Could not create TAP device: ") + strerror(errno));

        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0)
            throw std::runtime_error(std::string("Could not create AF_INET socket: ") + strerror(errno));

        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

        err = ioctl(sock, SIOCSIFFLAGS, &ifr);
        if (err < 0)
            throw std::runtime_error(std::string("Could not set UP flags for TAP device: ") + strerror(errno));
        close(sock);
    }

    void feed(const char *buf, int len) override {
        write(fd, buf, len);
    }

    const char *name() const override {
        return ifr.ifr_name;
    }

    virtual ~Tap() {
        if (fd >= 0)
            close(fd);
    }
};

struct Server {
    int sock;
    char buf[BUFSIZ];
    Server(const char *listenip, int port) {
        sockaddr_in saddr;

        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(listenip);
        saddr.sin_port = htons(port);

        sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0)
            throw std::runtime_error(std::string("Could not create UDP socket: ") + strerror(errno));

        int err = bind(sock, (sockaddr *)&saddr, sizeof(saddr));
        if (err < 0)
            throw std::runtime_error(std::string("Could not bind: ") + strerror(errno));
    }
    void process(Feeder *f) {
        while (true) {
            sockaddr_in caddr;
            socklen_t fromlen = sizeof(caddr);
            int recvsize = recvfrom(sock, buf, BUFSIZ, 0,
                    (sockaddr *)&caddr, &fromlen);

            if (recvsize < 0)
                throw std::runtime_error(std::string("Recvfrom failed: ") + strerror(errno));

            f->feed(buf, recvsize);
        }
    }
    ~Server() {
        if (sock >= 0)
            close(sock);
    }
};

int usage(const char *argv0) {
    std::cerr << "USAGE: " << argv0 << " <bind ip> <bind port>" << std::endl;
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3)
        return usage(argv[0]);
    try {
        std::unique_ptr<Feeder> f;
//        if (useTap)
            f = std::unique_ptr<Feeder>(new Tap());
//        else
//            f = std::unique_ptr<Feeder>(new Fifo());
        std::cout << "Created " << f->name() << std::endl;
        Server s(argv[1], atoi(argv[2]));
        s.process(f.get());
    } catch (const std::runtime_error &e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}
