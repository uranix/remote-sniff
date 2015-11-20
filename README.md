# remote-sniff
Libpcap based remote sniffer

Consists of three components

* Sniffer. Grabs packets from an interface and sends them over UDP to a given address. Requires root due to libpcap

* Feeder. Creates a TAP device, listens for UDP packets on given address and sends them to the TAP device. Requires root due to TAP creation

* Wireshark (standalone). Reads the TAP device and shows the packets. The device should appear nicely in the interface list.

Example: 

Consider a router with address `192.168.1.1` that routes traffic for `192.168.1.0/24` subnet on `eth1` interface. Also consider a remote PC with `1.2.3.4` address and Wireshark installed.

```
root@router # ./sniffer eth1 1.2.3.4 31337
```

```
root@pc # ./feeder 0.0.0.0 31337 &
Created tap0
...
user@pc $ wireshark -k -i tap0
```
