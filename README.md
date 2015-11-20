# remote-sniff
Libpcap based remote sniffer

Consists of three components

* Sniffer. Grabs packets from an interface and sends them over UDP to a given address. Requires root due to libpcap

* Feeder. Creates either a TAP device or a named pipe (FIFO), listens for UDP packets on given address and sends them to the feeding device. Requires root if TAP mode is used

* Wireshark (standalone). Reads the feeding device and shows the packets. The TAP device should appear nicely in the interface list, the FIFO should be opened explicitely

Example:

Consider a router with address `192.168.1.1` that routes traffic for `192.168.1.0/24` subnet on `eth1` interface. Also consider a remote PC with `1.2.3.4` address and Wireshark installed.

```
root@router # ./sniffer eth1 1.2.3.4 31337
```

On the PC run

```
root@pc # ./feeder -t 0.0.0.0 31337 &
Created tap0
...
user@pc $ wireshark -k -i tap0
```

or

```
user@pc $ ./feeder -f 0.0.0.0 31337 &
Created /tmp/feed5aY3Dg/fifo
...
user@pc $ wireshark -k -i /tmp/feed5aY3Dg/fifo
```
