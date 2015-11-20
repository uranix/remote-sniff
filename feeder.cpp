#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/limits.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/signal.h>
#include <sys/time.h>

#include <fcntl.h>
#include <errno.h>
#include <cstring>
#include <unistd.h>

#include <iostream>
#include <stdexcept>
#include <string>

#include <cstdint>

#include <memory>

struct Feeder {
    int fd;
    virtual ssize_t feed(const char *buf, const int len) {
        std::cout << ".";
        std::cout.flush();
        return write(fd, buf, len);
    }
    virtual const char *name() const = 0;
    virtual ~Feeder() {}
};

struct Tap : public Feeder {
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

    const char *name() const override {
        return ifr.ifr_name;
    }

    virtual ~Tap() {
        if (fd >= 0)
            close(fd);
    }
};

struct Fifo : public Feeder {
    char dirname[PATH_MAX];
    char *tmpdir;
    char namebuf[PATH_MAX];
    Fifo() {
        strcpy(dirname, "/tmp/feedXXXXXX");
        tmpdir = mkdtemp(dirname);
        if (!tmpdir)
            throw std::runtime_error(std::string("Could not create temp directory: ") + strerror(errno));
        strcpy(namebuf, tmpdir);
        strcat(namebuf, "/fifo");
        int err;
        err = mkfifo(namebuf, 0600);
        if (err < 0)
            throw std::runtime_error(std::string("Could not create fifo: ") + strerror(errno));

        std::cout << "Waiting for someone to attach to " << namebuf << std::endl;
        fd = open(namebuf, O_WRONLY);
        if (fd < 0)
            throw std::runtime_error(std::string("Could not open fifo: ") + strerror(errno));

        writeHeader();
    }
    void writeHeader() {
        struct pcap_hdr_s {
            uint32_t magic_number;   /* magic number */
            uint16_t version_major;  /* major version number */
            uint16_t version_minor;  /* minor version number */
            int32_t  thiszone;       /* GMT to local correction */
            uint32_t sigfigs;        /* accuracy of timestamps */
            uint32_t snaplen;        /* max length of captured packets, in octets */
            uint32_t network;        /* data link type */
        } hdr;
        hdr.magic_number = 0xa1b2c3d4;
        hdr.version_major = 2;
        hdr.version_minor = 4;
        hdr.thiszone = 0;
        hdr.sigfigs = 0;
        hdr.snaplen = 65536;
        hdr.network = 1;

        write(fd, &hdr, sizeof(hdr));
    }
    const char *name() const override {
        return namebuf;
    }
    virtual ssize_t feed(const char *buf, const int len) {
        struct pcaprec_hdr_s {
            uint32_t ts_sec;         /* timestamp seconds */
            uint32_t ts_usec;        /* timestamp microseconds */
            uint32_t incl_len;       /* number of octets of packet saved in file */
            uint32_t orig_len;       /* actual length of packet */
        } hdr;
        timeval tv;
        gettimeofday(&tv, nullptr);
        hdr.ts_sec = tv.tv_sec;
        hdr.ts_usec = tv.tv_usec;
        hdr.incl_len = hdr.orig_len = len;

        write(fd, &hdr, sizeof(hdr));
        return Feeder::feed(buf, len);
    }
    ~Fifo() {
        if (fd >= 0)
            close(fd);
        if (tmpdir) {
            unlink(name());
            rmdir(tmpdir);
        }
    }
};

bool alive = true;
void interrupt(int signo) {
    std::cerr << "Interrupted" << std::endl;
    alive = false;
}

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
        while (alive) {
            sockaddr_in caddr;
            socklen_t fromlen = sizeof(caddr);
            int recvsize = recvfrom(sock, buf, BUFSIZ, 0,
                    (sockaddr *)&caddr, &fromlen);

            if (recvsize < 0)
                throw std::runtime_error(std::string("Recvfrom failed: ") + strerror(errno));

            ssize_t err = f->feed(buf, recvsize);
            if (err < 0)
                alive = false;
        }
    }
    ~Server() {
        if (sock >= 0)
            close(sock);
    }
};

int usage(const char *argv0) {
    std::cerr << "USAGE: " << argv0 << " -t/-f <bind ip> <bind port>" << std::endl
        << "\t use -t to create a TAP device (requires root) and -f to create a fifo" << std::endl;
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 4)
        return usage(argv[0]);
    try {
        struct sigaction sa;
        sa.sa_handler = interrupt;
        sa.sa_flags = 0;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, nullptr);
        signal(SIGPIPE, SIG_IGN);

        std::unique_ptr<Feeder> f;
        if (strcmp(argv[1], "-t") == 0)
            f = std::unique_ptr<Feeder>(new Tap());
        else
            f = std::unique_ptr<Feeder>(new Fifo());
        std::cout << "Created " << f->name() << std::endl;
        Server s(argv[2], atoi(argv[3]));
        s.process(f.get());
        std::cout << std::endl;
    } catch (const std::runtime_error &e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}
