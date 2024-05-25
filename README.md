## Packet_Sniffer

  

This programs captures packets on various protocols and displays them.

  

## Getting Started

  

First, make sure to install a c compiler and libpcap library
and run the command at the root directory:

  

``` 
make
```

It will generate a executable.

Run the executable with command line arguments

  

```
./[executable][filter for protocol][interface to capture packets]
```
Example :  ./sniffer "tcp port 80" en0

  
  

Open log.txt file to see the result.

  

## Learn More

  

To learn more about libpcap, take a look at the following resources:

  

- [libpcap Documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html#lbAK) - learn about packet capturing.
